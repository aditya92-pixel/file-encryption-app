import os
import sys
import struct
import tempfile
import threading
import argparse
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_DND = True
except ImportError:
    HAS_DND = False

if HAS_DND:
    class AppTk(TkinterDnD.Tk): pass
else:
    class AppTk(tk.Tk): pass


class CryptoEngine:
    """Handles the cryptographic logic and custom file format for the application."""
    
    MAGIC = b"ENCF1"
    VERSION = b"\x01"
    KDF_ALGO_PBKDF2 = b"\x01"
    ITERATIONS = 600_000
    CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB

    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
        """Derives a 32-byte key using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def encrypt_file(in_path: str, out_path: str, password: str, progress_callback=None) -> None:
        """Encrypts a file of any format in chunks using AES-256-GCM."""
        file_size = os.path.getsize(in_path)
        salt = os.urandom(16)
        
        key = CryptoEngine.derive_key(password, salt, CryptoEngine.ITERATIONS)
        aesgcm = AESGCM(key)

        orig_filename = os.path.basename(in_path).encode("utf-8")
        
        header_bytes = (
            CryptoEngine.MAGIC +
            CryptoEngine.VERSION +
            CryptoEngine.KDF_ALGO_PBKDF2 +
            struct.pack("<I", CryptoEngine.ITERATIONS) +
            salt +
            struct.pack("<H", len(orig_filename)) +
            orig_filename +
            struct.pack("<I", CryptoEngine.CHUNK_SIZE)
        )
        
        fd_out, temp_out_path = tempfile.mkstemp(dir=os.path.dirname(out_path), prefix=".enc_tmp")
        try:
            with open(in_path, "rb") as f_in, os.fdopen(fd_out, "wb") as f_out:
                f_out.write(header_bytes)
                processed = 0
                if progress_callback: progress_callback(0)
                    
                is_first_chunk = True
                while True:
                    chunk = f_in.read(CryptoEngine.CHUNK_SIZE)
                    if not chunk and not is_first_chunk:
                        break  # Ensures at least one chunk (even empty) is written to authenticate header
                    
                    nonce = os.urandom(12)
                    # The entire header is authenticated within each chunk
                    ciphertext = aesgcm.encrypt(nonce, chunk, header_bytes)
                    f_out.write(nonce + ciphertext)
                    
                    processed += len(chunk)
                    if progress_callback and file_size > 0:
                        progress_callback(processed / file_size)
                        
                    is_first_chunk = False
                    if not chunk: break
                        
            if os.path.exists(out_path): os.remove(out_path)
            os.rename(temp_out_path, out_path)
        except Exception as e:
            if os.path.exists(temp_out_path): os.remove(temp_out_path)
            raise e
        finally:
            key, password = b"", ""  # Discard references to secrets

    @staticmethod
    def decrypt_file(in_path: str, out_path: str, password: str, progress_callback=None) -> str:
        """Decrypts a file in chunks. Returns the original filename."""
        file_size = os.path.getsize(in_path)
        fd_out, temp_out_path = tempfile.mkstemp(dir=os.path.dirname(out_path), prefix=".dec_tmp")
        
        try:
            with open(in_path, "rb") as f_in, os.fdopen(fd_out, "wb") as f_out:
                magic = f_in.read(5)
                if magic != CryptoEngine.MAGIC:
                    raise ValueError("Not a valid encrypted file or missing magic bytes.")
                version = f_in.read(1)
                if version != CryptoEngine.VERSION:
                    raise ValueError(f"Unsupported version byte: {version}")
                
                kdf_algo = f_in.read(1)
                iterations_bytes = f_in.read(4)
                iterations = struct.unpack("<I", iterations_bytes)[0]
                salt = f_in.read(16)
                
                len_bytes = f_in.read(2)
                orig_filename_len = struct.unpack("<H", len_bytes)[0]
                orig_filename_bytes = f_in.read(orig_filename_len)
                orig_filename = orig_filename_bytes.decode("utf-8")
                
                chunk_size_bytes = f_in.read(4)
                chunk_size = struct.unpack("<I", chunk_size_bytes)[0]
                
                header_bytes = (
                    magic + version + kdf_algo + iterations_bytes + salt +
                    len_bytes + orig_filename_bytes + chunk_size_bytes
                )
                
                key = CryptoEngine.derive_key(password, salt, iterations)
                aesgcm = AESGCM(key)
                
                processed = len(header_bytes)
                if progress_callback: progress_callback(processed / file_size if file_size > 0 else 0)
                
                read_size = 12 + chunk_size + 16
                while True:
                    chunk = f_in.read(read_size)
                    if not chunk: break
                    if len(chunk) < 28:
                        raise ValueError("File is corrupted or truncated.")
                        
                    nonce, ciphertext = chunk[:12], chunk[12:]
                    try:
                        plaintext = aesgcm.decrypt(nonce, ciphertext, header_bytes)
                    except InvalidTag:
                        raise ValueError("Wrong password or file is corrupted.")
                        
                    f_out.write(plaintext)
                    processed += len(chunk)
                    if progress_callback and file_size > 0:
                        progress_callback(processed / file_size)
                        
            if os.path.exists(out_path): os.remove(out_path)
            os.rename(temp_out_path, out_path)
            return orig_filename
        except Exception as e:
            if os.path.exists(temp_out_path): os.remove(temp_out_path)
            raise e
        finally:
            key, password = b"", ""

    @staticmethod
    def peek_original_filename(in_path: str) -> str | None:
        """Reads the unencrypted header of an archive to guess the original filename."""
        try:
            with open(in_path, "rb") as f_in:
                if f_in.read(5) != CryptoEngine.MAGIC: return None
                f_in.read(1) # version
                f_in.read(1) # kdf
                f_in.read(4) # iterations
                f_in.read(16) # salt
                len_bytes = f_in.read(2)
                if len(len_bytes) < 2: return None
                orig_len = struct.unpack("<H", len_bytes)[0]
                return f_in.read(orig_len).decode("utf-8")
        except Exception:
            return None


class App(AppTk):
    """Main Application GUI Window."""
    def __init__(self):
        super().__init__()
        self.title("Encrypt / Decrypt File")
        self.resizable(False, False)
        
        w, h = 500, 260
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

        self.last_dir = ""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_status_bar()
        self.bind("<Return>", self.on_enter_pressed)

    def _build_encrypt_tab(self):
        f = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(f, text="Encrypt File")
        
        ttk.Label(f, text="File to encrypt:").grid(row=0, column=0, sticky="e", pady=2)
        self.enc_file_in = ttk.Entry(f, state="readonly", width=38)
        self.enc_file_in.grid(row=0, column=1, padx=5, pady=2, sticky="we")
        btn_frame = ttk.Frame(f)
        btn_frame.grid(row=0, column=2, padx=5, pady=2)
        self.btn_enc_browse = ttk.Button(btn_frame, text="File", width=5, command=self.browse_enc_in)
        self.btn_enc_browse.pack(side="left", padx=(0, 2))
        self.btn_enc_browse_dir = ttk.Button(btn_frame, text="Folder", width=6, command=self.browse_enc_in_dir)
        self.btn_enc_browse_dir.pack(side="left")
        
        ttk.Label(f, text="File destination:").grid(row=1, column=0, sticky="e", pady=2)
        self.enc_file_out = ttk.Entry(f, state="readonly", width=38)
        self.enc_file_out.grid(row=1, column=1, padx=5, pady=2, sticky="we")
        self.btn_enc_change = ttk.Button(f, text="Change", width=10, command=self.change_enc_out)
        self.btn_enc_change.grid(row=1, column=2, padx=5, pady=2)
        
        ttk.Separator(f, orient="horizontal").grid(row=2, column=0, columnspan=3, sticky="we", pady=5)
        
        ttk.Label(f, text="Type password:").grid(row=3, column=0, sticky="e", pady=2)
        self.enc_pw = ttk.Entry(f, show="*", width=38)
        self.enc_pw.grid(row=3, column=1, padx=5, pady=2, sticky="we")
        
        ttk.Label(f, text="Confirm password:").grid(row=4, column=0, sticky="e", pady=2)
        self.enc_pw_conf = ttk.Entry(f, show="*", width=38)
        self.enc_pw_conf.grid(row=4, column=1, padx=5, pady=2, sticky="we")
        
        self.btn_enc_do = tk.Button(f, text="Encrypt", font=("Tahoma", 9, "bold"), command=self.do_encrypt)
        self.btn_enc_do.grid(row=3, column=2, rowspan=2, padx=5, pady=2, sticky="nsew")
        
        opts = ttk.Frame(f)
        opts.grid(row=5, column=0, columnspan=3, pady=(10, 0), sticky="w")
        self.enc_del_var = tk.BooleanVar()
        ttk.Checkbutton(opts, text="Delete original", variable=self.enc_del_var).pack(side="left", padx=5)
        self.enc_show_var = tk.BooleanVar()
        ttk.Checkbutton(opts, text="Show passwords", variable=self.enc_show_var, command=self.toggle_enc_pw).pack(side="left", padx=5)

        if HAS_DND:
            self.enc_file_in.drop_target_register(DND_FILES)
            self.enc_file_in.dnd_bind('<<Drop>>', lambda e: self.set_enc_in(self._clean_dnd(e.data)))

    def _build_decrypt_tab(self):
        f = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(f, text="Decrypt File")
        
        ttk.Label(f, text="File to decrypt:").grid(row=0, column=0, sticky="e", pady=2)
        self.dec_file_in = ttk.Entry(f, state="readonly", width=38)
        self.dec_file_in.grid(row=0, column=1, padx=5, pady=2, sticky="we")
        self.btn_dec_browse = ttk.Button(f, text="Browse", width=10, command=self.browse_dec_in)
        self.btn_dec_browse.grid(row=0, column=2, padx=5, pady=2)
        
        ttk.Label(f, text="File destination:").grid(row=1, column=0, sticky="e", pady=2)
        self.dec_file_out = ttk.Entry(f, state="readonly", width=38)
        self.dec_file_out.grid(row=1, column=1, padx=5, pady=2, sticky="we")
        self.btn_dec_change = ttk.Button(f, text="Change", width=10, command=self.change_dec_out)
        self.btn_dec_change.grid(row=1, column=2, padx=5, pady=2)
        
        ttk.Separator(f, orient="horizontal").grid(row=2, column=0, columnspan=3, sticky="we", pady=5)
        
        ttk.Label(f, text="Type password:").grid(row=3, column=0, sticky="e", pady=2)
        self.dec_pw = ttk.Entry(f, show="*", width=38)
        self.dec_pw.grid(row=3, column=1, padx=5, pady=2, sticky="we")
        
        self.btn_dec_do = tk.Button(f, text="Decrypt", font=("Tahoma", 9, "bold"), command=self.do_decrypt)
        self.btn_dec_do.grid(row=3, column=2, padx=5, pady=2, sticky="nsew")
        
        opts = ttk.Frame(f)
        opts.grid(row=4, column=0, columnspan=3, pady=(10, 0), sticky="w")
        self.dec_del_var = tk.BooleanVar()
        ttk.Checkbutton(opts, text="Delete encrypted file", variable=self.dec_del_var).pack(side="left", padx=5)
        self.dec_show_var = tk.BooleanVar()
        ttk.Checkbutton(opts, text="Show password", variable=self.dec_show_var, command=self.toggle_dec_pw).pack(side="left", padx=5)

        if HAS_DND:
            self.dec_file_in.drop_target_register(DND_FILES)
            self.dec_file_in.dnd_bind('<<Drop>>', lambda e: self.set_dec_in(self._clean_dnd(e.data)))

    def _build_status_bar(self):
        sf = tk.Frame(self)
        sf.pack(side="bottom", fill="x")
        self.status_lbl = ttk.Label(sf, text="Ready")
        self.status_lbl.pack(side="left", padx=5)
        self.progress = ttk.Progressbar(sf, orient="horizontal", mode="determinate", length=150)
        self.progress.pack(side="right", padx=5, pady=2)

    def _clean_dnd(self, path: str) -> str:
        return path[1:-1] if path.startswith('{') and path.endswith('}') else path.split()[0]

    def on_enter_pressed(self, event):
        if self.notebook.index(self.notebook.select()) == 0:
            self.do_encrypt()
        else:
            self.do_decrypt()

    def toggle_enc_pw(self):
        char = "" if self.enc_show_var.get() else "*"
        self.enc_pw.config(show=char); self.enc_pw_conf.config(show=char)

    def toggle_dec_pw(self):
        self.dec_pw.config(show="" if self.dec_show_var.get() else "*")

    def browse_enc_in(self):
        # Allow any file format
        path = filedialog.askopenfilename(initialdir=self.last_dir, filetypes=[("All Files", "*.*")])
        if path: self.set_enc_in(path)

    def browse_enc_in_dir(self):
        path = filedialog.askdirectory(initialdir=self.last_dir)
        if path: self.set_enc_in(path)

    def change_enc_out(self):
        if not self.enc_file_in.get(): return
        path = filedialog.asksaveasfilename(initialdir=self.last_dir)
        if path:
            self.last_dir = os.path.dirname(path)
            self.enc_file_out.config(state=tk.NORMAL); self.enc_file_out.delete(0, tk.END)
            self.enc_file_out.insert(0, path); self.enc_file_out.config(state="readonly")

    def set_enc_in(self, path: str):
        self.last_dir = os.path.dirname(path)
        self.enc_file_in.config(state=tk.NORMAL); self.enc_file_in.delete(0, tk.END)
        self.enc_file_in.insert(0, path); self.enc_file_in.config(state="readonly")
        
        base_name = os.path.basename(path)
        if os.path.isdir(path):
            new_name = base_name + ".zip.encrypt"
        else:
            name, ext = os.path.splitext(base_name)
            new_name = name + ("_" + ext[1:] if ext else "") + ".encrypt"
            
        out_path = os.path.join(self.last_dir, new_name)
        
        self.enc_file_out.config(state=tk.NORMAL); self.enc_file_out.delete(0, tk.END)
        self.enc_file_out.insert(0, out_path); self.enc_file_out.config(state="readonly")

    def browse_dec_in(self):
        # Look for encrypted files by default, but allow all
        path = filedialog.askopenfilename(initialdir=self.last_dir, filetypes=[("Encrypted", "*.encrypt"), ("All", "*.*")])
        if path: self.set_dec_in(path)

    def change_dec_out(self):
        if not self.dec_file_in.get(): return
        path = filedialog.asksaveasfilename(initialdir=self.last_dir)
        if path:
            self.last_dir = os.path.dirname(path)
            self.dec_file_out.config(state=tk.NORMAL); self.dec_file_out.delete(0, tk.END)
            self.dec_file_out.insert(0, path); self.dec_file_out.config(state="readonly")

    def set_dec_in(self, path: str):
        self.last_dir = os.path.dirname(path)
        self.dec_file_in.config(state=tk.NORMAL); self.dec_file_in.delete(0, tk.END)
        self.dec_file_in.insert(0, path); self.dec_file_in.config(state="readonly")
        
        orig_name = CryptoEngine.peek_original_filename(path)
        if orig_name:
            out_path = os.path.join(self.last_dir, orig_name)
        else:
            base_name = os.path.basename(path)
            if base_name.endswith(".encrypt"):
                rest = base_name[:-8]
                idx = rest.rfind("_")
                out_path = os.path.join(self.last_dir, rest[:idx] + "." + rest[idx+1:] if idx != -1 else rest)
            else:
                out_path = os.path.join(self.last_dir, base_name + ".decrypted")
                
        self.dec_file_out.config(state=tk.NORMAL); self.dec_file_out.delete(0, tk.END)
        self.dec_file_out.insert(0, out_path); self.dec_file_out.config(state="readonly")

    def set_ui_locked(self, locked: bool):
        st = "disabled" if locked else "normal"
        for w in (self.enc_pw, self.enc_pw_conf, self.btn_enc_do, self.btn_enc_browse, self.btn_enc_browse_dir, self.btn_enc_change,
                  self.dec_pw, self.btn_dec_do, self.btn_dec_browse, self.btn_dec_change):
            w.config(state=st)

    def do_encrypt(self):
        in_p, out_p = self.enc_file_in.get(), self.enc_file_out.get()
        pw1, pw2 = self.enc_pw.get(), self.enc_pw_conf.get()
        
        if not in_p or not os.path.exists(in_p): return messagebox.showerror("Error", "Source does not exist.")
        if in_p == out_p: return messagebox.showerror("Error", "Source and destination cannot be the same.")
        if len(pw1) < 6: return messagebox.showwarning("Weak Password", "Password must be at least 6 characters.")
        if pw1 != pw2: return messagebox.showerror("Error", "Passwords do not match.")
        
        if os.path.exists(out_p) and not messagebox.askyesno("Overwrite?", f"Destination exists. Overwrite?\n{out_p}"):
            return
            
        self.set_ui_locked(True)
        self.status_lbl.config(text="Encrypting...")
        
        def task():
            temp_zip_path = None
            path_to_encrypt = in_p
            try:
                if os.path.isdir(in_p):
                    self.after(0, lambda: self.status_lbl.config(text="Packing folder (fast)..."))
                    fd, temp_zip = tempfile.mkstemp(suffix=".zip")
                    os.close(fd)
                    import zipfile
                    with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_STORED) as zf:
                        for root, _, files in os.walk(in_p):
                            for file in files:
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path, in_p)
                                zf.write(file_path, arcname)
                    path_to_encrypt = temp_zip
                    temp_zip_path = temp_zip
                    self.after(0, lambda: self.status_lbl.config(text="Encrypting..."))

                last_pct = [-1]
                def prog_cb(f):
                    pct = int(f * 100)
                    if pct > last_pct[0]:
                        last_pct[0] = pct
                        self.after_idle(lambda p=pct: self._update_prog(p))
                
                CryptoEngine.encrypt_file(path_to_encrypt, out_p, pw1, prog_cb)
                sz = os.path.getsize(out_p)
                self.after(0, lambda: self._on_success("Encryption Successful", f"Saved to:\n{out_p}\nSize: {sz} bytes", in_p, True))
            except Exception as e:
                self.after(0, lambda e=e: self._on_error("Encryption Failed", str(e)))
            finally:
                if temp_zip_path and os.path.exists(temp_zip_path):
                    try: os.remove(temp_zip_path)
                    except: pass
                
        threading.Thread(target=task, daemon=True).start()

    def do_decrypt(self):
        in_p, out_p = self.dec_file_in.get(), self.dec_file_out.get()
        pw = self.dec_pw.get()
        
        if not in_p or not os.path.exists(in_p): return messagebox.showerror("Error", "Source file does not exist.")
        if in_p == out_p: return messagebox.showerror("Error", "Source and destination cannot be the same.")
        if not pw: return messagebox.showwarning("Error", "Password is required.")
        
        if os.path.exists(out_p) and not messagebox.askyesno("Overwrite?", f"Destination exists. Overwrite?\n{out_p}"):
            return
            
        self.set_ui_locked(True)
        self.status_lbl.config(text="Decrypting...")
        
        def task():
            try:
                last_pct = [-1]
                def prog_cb(f):
                    pct = int(f * 100)
                    if pct > last_pct[0]:
                        last_pct[0] = pct
                        self.after_idle(lambda p=pct: self._update_prog(p))
                
                CryptoEngine.decrypt_file(in_p, out_p, pw, prog_cb)
                sz = os.path.getsize(out_p)
                self.after(0, lambda: self._on_success("Decryption Successful", f"Saved to:\n{out_p}\nSize: {sz} bytes", in_p, False))
            except Exception as e:
                self.after(0, lambda e=e: self._on_error("Decryption Failed", str(e)))
                
        threading.Thread(target=task, daemon=True).start()

    def _update_prog(self, pct):
        self.progress["value"] = pct
        self.status_lbl.config(text=f"Progress: {pct}%")

    def _on_error(self, title, msg):
        self.set_ui_locked(False)
        self.status_lbl.config(text="Error")
        self.progress["value"] = 0
        messagebox.showerror(title, msg)

    def _on_success(self, title, msg, in_p, is_encrypt):
        self.set_ui_locked(False)
        self.status_lbl.config(text="Ready")
        self.progress["value"] = 0
        
        if is_encrypt:
            self.enc_pw.delete(0, tk.END); self.enc_pw_conf.delete(0, tk.END)
            if self.enc_del_var.get() and messagebox.askyesno("Delete Original", f"Delete original file?\n{in_p}"):
                try: os.remove(in_p)
                except OSError as e: messagebox.showwarning("Warning", f"Could not delete: {e}")
        else:
            self.dec_pw.delete(0, tk.END)
            if self.dec_del_var.get() and messagebox.askyesno("Delete Original", f"Delete encrypted file?\n{in_p}"):
                try: os.remove(in_p)
                except OSError as e: messagebox.showwarning("Warning", f"Could not delete: {e}")
                
        messagebox.showinfo(title, msg)


def run_unit_tests():
    """Runs a quick sanity check to ensure cryptography functions are working accurately."""
    print("Running unit tests...")
    with tempfile.TemporaryDirectory() as d:
        in_f, enc_f, dec_f = os.path.join(d, "test.txt"), os.path.join(d, "test.enc"), os.path.join(d, "test_dec.txt")
        data = os.urandom(2.5 * 1024 * 1024)
        with open(in_f, "wb") as f: f.write(data)
            
        print("1. Encrypting...")
        CryptoEngine.encrypt_file(in_f, enc_f, "strong_password")
        
        print("2. Decrypting with correct password...")
        CryptoEngine.decrypt_file(enc_f, dec_f, "strong_password")
        with open(dec_f, "rb") as f: assert data == f.read(), "Data mismatch!"
        
        print("3. Decrypting with wrong password...")
        try:
            CryptoEngine.decrypt_file(enc_f, dec_f, "wrong_password")
            assert False, "Should have thrown an exception!"
        except ValueError as e:
            assert "Wrong password" in str(e) or "corrupted" in str(e)
            
        print("All tests passed successfully.")

def main():
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Encrypt / Decrypt File CLI")
        subparsers = parser.add_subparsers(dest="mode", help="Mode to run")
        
        p_enc = subparsers.add_parser("encrypt", help="Encrypt a file")
        p_enc.add_argument("in_file", help="Input file path")
        p_enc.add_argument("out_file", help="Output file path")
        
        p_dec = subparsers.add_parser("decrypt", help="Decrypt a file")
        p_dec.add_argument("in_file", help="Input file path")
        p_dec.add_argument("out_file", help="Output file path")
        
        subparsers.add_parser("test", help="Run unit tests")
        args = parser.parse_args()
        
        if args.mode == "test":
            run_unit_tests()
        elif args.mode in ("encrypt", "decrypt"):
            import getpass
            password = getpass.getpass("Password: ")
            if args.mode == "encrypt":
                pw2 = getpass.getpass("Confirm password: ")
                if password != pw2: sys.exit("Passwords do not match.")
                print("Encrypting...")
                try:
                    CryptoEngine.encrypt_file(args.in_file, args.out_file, password)
                    print(f"Success. Saved to {args.out_file}")
                except Exception as e: sys.exit(f"Encryption failed: {e}")
            else:
                print("Decrypting...")
                try:
                    CryptoEngine.decrypt_file(args.in_file, args.out_file, password)
                    print(f"Success. Saved to {args.out_file}")
                except Exception as e: sys.exit(f"Decryption failed: {e}")
    else:
        App().mainloop()

if __name__ == "__main__":
    main()

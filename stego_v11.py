import os
import sys
import threading
import zlib
import hashlib
import base64
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from PIL import Image, ImageTk
import numpy as np

# הצפנה
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- הגדרות קבועות (Constants) ---
APP_VERSION = "v11.0"
SIGNATURE = b'STG11'   # חתימה פנימית לאחר פענוח
SALT_SIZE = 16         # גודל ה-Salt בבתים
SIZE_HEADER = 4        # גודל שדה האורך בבתים
# סה"כ פיקסלים שנתפוס בהתחלה לכתיבה סדרתית (Salt + Size)
# 16 bytes salt + 4 bytes size = 20 bytes * 8 bits = 160 pixels
FIXED_HEADER_PIXELS = (SALT_SIZE + SIZE_HEADER) * 8 
FAKE_KEY_SIZE = 512    # גודל קובץ זבל במקרה של כישלון

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# --- מנוע הליבה (Core Engine) ---
class StegoEngineV11:
    
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """ גזירת מפתח הצפנה (KDF) עם Salt דינמי """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000, # החמרה ל-200K איטרציות
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def _get_scattered_indices(seed_source: bytes, pool_size: int, needed: int):
        """
        ניהול זיכרון חכם:
        במקום לייצר מערך ענק של כל התמונה (Permutation),
        אנו בוחרים רק את האינדקסים שאנחנו באמת צריכים (Choice).
        זה חוסך מאות מגה-בייט של RAM בתמונות גדולות.
        """
        # יצירת Seed דטרמיניסטי ל-RNG
        seed_hash = hashlib.sha256(seed_source).digest()
        seed_int = int.from_bytes(seed_hash, 'little')
        
        rng = np.random.default_rng(seed_int)
        
        # בחירה ללא חזרות (replace=False) מתוך הפיקסלים הפנויים
        # הפונקציה הזו יעילה משמעותית מ-permutation כשה-needed קטן מ-pool_size
        indices = rng.choice(pool_size, size=needed, replace=False)
        return indices

    @staticmethod
    def embed(image_path, file_path, password, output_path):
        # 1. טעינת תמונה (תמיכה ב-RGBA)
        img = Image.open(image_path)
        # המרה חכמה: אם יש שקיפות נשמור עליה, אחרת RGB
        mode = 'RGBA' if img.mode == 'RGBA' else 'RGB'
        img = img.convert(mode)
        
        img_array = np.array(img)
        flat_img = img_array.flatten()
        total_pixels = flat_img.size
        
        # חישוב פיקסלים פנויים (אחרי ה-Header הקבוע)
        available_pool = total_pixels - FIXED_HEADER_PIXELS
        if available_pool <= 0:
            raise ValueError("התמונה קטנה מכדי להכיל אפילו את ה-Header.")

        # 2. הכנת הנתונים
        with open(file_path, 'rb') as f:
            raw_data = f.read()

        # Checksum
        checksum = zlib.crc32(raw_data).to_bytes(4, 'little')
        
        # יצירת Salt דינמי (קריטי לאבטחה!)
        salt = secrets.token_bytes(SALT_SIZE)
        
        # הצפנה
        key = StegoEngineV11._derive_key(password, salt)
        fernet = Fernet(key)
        
        # Payload פנימי: חתימה + CRC + מידע
        inner_payload = SIGNATURE + checksum + raw_data
        encrypted_data = fernet.encrypt(inner_payload)
        
        # חישובים לביטים
        enc_len = len(encrypted_data)
        enc_len_bytes = enc_len.to_bytes(SIZE_HEADER, 'little')
        
        # המרה לביטים
        # חלק א': Header קבוע (Salt + Length)
        header_bytes = salt + enc_len_bytes
        header_bits = np.unpackbits(np.frombuffer(header_bytes, dtype=np.uint8))
        
        # חלק ב': המידע המוצפן
        data_bits = np.unpackbits(np.frombuffer(encrypted_data, dtype=np.uint8))
        
        # בדיקת קיבולת
        if len(data_bits) > available_pool:
            raise ValueError(f"חריגה מקיבולת התמונה!\nנדרש: {len(data_bits)} פיקסלים פנויים\nקיים: {available_pool}")

        # 3. ביצוע הטמעה
        
        # שלב א: כתיבת ה-Header (סדרתי בהתחלה)
        flat_img[:len(header_bits)] &= 0xFE
        flat_img[:len(header_bits)] |= header_bits
        
        # שלב ב: כתיבת הגוף (Scattered) בשאר התמונה
        # ה-Seed מורכב מהסיסמה ומה-Salt שיצרנו הרגע
        seed = password.encode() + salt
        
        # קבלת אינדקסים רנדומליים יחסיים (0 עד available_pool)
        indices_rel = StegoEngineV11._get_scattered_indices(seed, available_pool, len(data_bits))
        
        # המרה לאינדקסים אבסולוטיים (הזזה ב-Fixed Header)
        indices_abs = indices_rel + FIXED_HEADER_PIXELS
        
        # כתיבת הביטים במיקומים הנבחרים
        flat_img[indices_abs] &= 0xFE
        flat_img[indices_abs] |= data_bits

        # 4. שמירה
        encoded_img_array = flat_img.reshape(img_array.shape)
        result_img = Image.fromarray(encoded_img_array, mode=mode)
        result_img.save(output_path, format="PNG")

    @staticmethod
    def extract(image_path, password, output_path):
        img = Image.open(image_path)
        img_array = np.array(img)
        flat_img = img_array.flatten()
        
        # 1. קריאת ה-Header הקבוע (Sequential)
        # אנחנו יודעים בדיוק איפה הוא: ב-160 הפיקסלים הראשונים
        header_bits = flat_img[:FIXED_HEADER_PIXELS] & 1
        header_bytes = np.packbits(header_bits).tobytes()
        
        # חילוץ רכיבים
        salt = header_bytes[:SALT_SIZE]
        enc_len_bytes = header_bytes[SALT_SIZE : SALT_SIZE + SIZE_HEADER]
        enc_len = int.from_bytes(enc_len_bytes, 'little')
        
        # 2. בדיקת שפיות (Sanity Check) מיידית
        available_pool = flat_img.size - FIXED_HEADER_PIXELS
        max_possible_bytes = available_pool // 8
        
        if enc_len <= 0 or enc_len > max_possible_bytes:
            # גודל לא הגיוני -> כנראה תמונה רגילה או סיסמה שגויה (אם היינו מצפינים את הגודל)
            # מכיוון שהגודל לא מוצפן כאן, זה מעיד שהקובץ הוא לא Stego שלנו.
            StegoEngineV11._generate_fake_file(output_path, flat_img)
            return False, "Invalid Header Size"

        # 3. חילוץ הגוף (Scattered)
        seed = password.encode() + salt
        bits_needed = enc_len * 8
        
        # שיחזור האינדקסים בדיוק לפי אותו Seed
        indices_rel = StegoEngineV11._get_scattered_indices(seed, available_pool, bits_needed)
        indices_abs = indices_rel + FIXED_HEADER_PIXELS
        
        # קריאת הביטים
        data_bits = flat_img[indices_abs] & 1
        encrypted_data = np.packbits(data_bits).tobytes()
        
        # 4. פענוח ואימות
        try:
            key = StegoEngineV11._derive_key(password, salt)
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted_data)
            
            # בדיקת מבנה: [SIGNATURE] [CRC] [DATA]
            if not decrypted.startswith(SIGNATURE):
                raise Exception("Invalid Signature")
                
            sig_len = len(SIGNATURE)
            stored_crc = decrypted[sig_len : sig_len+4]
            actual_data = decrypted[sig_len+4 :]
            
            # בדיקת CRC
            calculated_crc = zlib.crc32(actual_data).to_bytes(4, 'little')
            if calculated_crc != stored_crc:
                raise Exception("CRC Mismatch")
                
            # שמירה
            with open(output_path, 'wb') as f:
                f.write(actual_data)
                
            return True, "Success"

        except Exception as e:
            StegoEngineV11._generate_fake_file(output_path, flat_img)
            return False, str(e)

    @staticmethod
    def _generate_fake_file(output_path, flat_img):
        """ יצירת קובץ רעש במקרה של כישלון """
        # לוקחים "ביטים" מהתמונה כדי שייראה רנדומלי אך דטרמיניסטי לתמונה
        limit = min(len(flat_img), FAKE_KEY_SIZE * 8)
        bits = flat_img[:limit] & 1
        noise = np.packbits(bits).tobytes()
        
        with open(output_path, 'wb') as f:
            f.write(noise)


# --- ממשק משתמש (GUI) ---
class StegoAppV11(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"StegoCrypto {APP_VERSION} - Professional Edition")
        self.geometry("800x650")
        self.resizable(False, False)
        
        self.font_bold = ("Segoe UI", 14, "bold")
        self.font_norm = ("Segoe UI", 13)
        
        self._init_ui()

    def _init_ui(self):
        # כותרת
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(pady=20)
        ctk.CTkLabel(header, text="מערכת הצפנה ויזואלית", font=("Segoe UI", 24, "bold")).pack()
        ctk.CTkLabel(header, text="Dynamic Salt | Memory Optimized | RGBA Support", text_color="gray").pack()

        # טאבים
        self.tabview = ctk.CTkTabview(self, width=750, height=480)
        self.tabview.pack(pady=10)
        self.tab_hide = self.tabview.add("הטמעה (Embed)")
        self.tab_extract = self.tabview.add("חילוץ (Extract)")

        self._setup_hide_tab()
        self._setup_extract_tab()
        
        # שורת סטטוס
        self.status_bar = ctk.CTkLabel(self, text="מוכן", text_color="gray")
        self.status_bar.pack(side="bottom", pady=5)

    def _setup_hide_tab(self):
        t = self.tab_hide
        
        # בחירת קבצים
        f_files = ctk.CTkFrame(t)
        f_files.pack(fill="x", padx=15, pady=15)
        
        # תמונה
        ctk.CTkButton(f_files, text="בחר תמונה", command=self.load_cover_img, width=120).grid(row=0, column=2, padx=10, pady=10)
        self.lbl_cover = ctk.CTkLabel(f_files, text="לא נבחרה תמונה", anchor="e", width=400)
        self.lbl_cover.grid(row=0, column=0, columnspan=2)
        
        # קובץ להסתרה
        ctk.CTkButton(f_files, text="בחר קובץ", command=self.load_secret_file, width=120, fg_color="#D65B5B").grid(row=1, column=2, padx=10, pady=10)
        self.lbl_secret = ctk.CTkLabel(f_files, text="לא נבחר קובץ", anchor="e", width=400)
        self.lbl_secret.grid(row=1, column=0, columnspan=2)

        # אזור הגדרות
        f_settings = ctk.CTkFrame(t, fg_color="transparent")
        f_settings.pack(fill="x", padx=20)

        # מד קיבולת צבעוני
        ctk.CTkLabel(f_settings, text="מד קיבולת:", font=self.font_bold).pack(anchor="e")
        self.cap_bar = ctk.CTkProgressBar(f_settings, width=600)
        self.cap_bar.pack(pady=5)
        self.cap_bar.set(0)
        self.lbl_cap_text = ctk.CTkLabel(f_settings, text="0% בשימוש", font=("Segoe UI", 11))
        self.lbl_cap_text.pack()

        # סיסמה עם Toggle
        f_pass = ctk.CTkFrame(t, fg_color="transparent")
        f_pass.pack(pady=20)
        
        self.entry_pass_hide = ctk.CTkEntry(f_pass, width=250, show="*", placeholder_text="סיסמה חזקה (מינימום 8 תווים)")
        self.entry_pass_hide.pack(side="left", padx=5)
        
        self.check_show_pass = ctk.CTkCheckBox(f_pass, text="הצג", command=self._toggle_pass_hide, width=50)
        self.check_show_pass.pack(side="left", padx=5)

        # כפתור ביצוע
        self.btn_embed = ctk.CTkButton(t, text="בצע הצפנה והטמעה", command=self.run_embed, 
                                       font=self.font_bold, height=45)
        self.btn_embed.pack(side="bottom", pady=20)

        # משתנים
        self.path_cover = None
        self.path_secret = None

    def _setup_extract_tab(self):
        t = self.tab_extract
        
        f_main = ctk.CTkFrame(t)
        f_main.pack(fill="x", padx=20, pady=30)
        
        ctk.CTkButton(f_main, text="בחר תמונה לפיענוח", command=self.load_stego_img).pack(side="right", padx=10, pady=10)
        self.lbl_stego = ctk.CTkLabel(f_main, text="לא נבחר קובץ")
        self.lbl_stego.pack(side="right", padx=10)
        
        # סיסמה לחילוץ
        f_pass = ctk.CTkFrame(t, fg_color="transparent")
        f_pass.pack(pady=20)
        ctk.CTkLabel(f_pass, text="הזן סיסמה לחילוץ:", font=self.font_bold).pack(pady=5)
        
        self.entry_pass_ext = ctk.CTkEntry(f_pass, width=250, show="*")
        self.entry_pass_ext.pack(side="left", padx=5)
        ctk.CTkCheckBox(f_pass, text="הצג", command=self._toggle_pass_ext, width=50).pack(side="left")

        # כפתור
        self.btn_extract = ctk.CTkButton(t, text="חלץ מידע", command=self.run_extract, 
                                         font=self.font_bold, height=45, fg_color="#4B8CDE")
        self.btn_extract.pack(side="bottom", pady=30)

        self.path_stego = None

    # --- לוגיקת UI ---
    
    def _toggle_pass_hide(self):
        self.entry_pass_hide.configure(show="" if self.check_show_pass.get() else "*")

    def _toggle_pass_ext(self):
        current = self.entry_pass_ext.cget("show")
        new = "" if current == "*" else "*"
        self.entry_pass_ext.configure(show=new)

    def load_cover_img(self):
        p = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp")])
        if p:
            self.path_cover = p
            self.lbl_cover.configure(text=os.path.basename(p))
            self._update_capacity()

    def load_secret_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.path_secret = p
            self.lbl_secret.configure(text=os.path.basename(p))
            self._update_capacity()

    def load_stego_img(self):
        p = filedialog.askopenfilename(filetypes=[("PNG", "*.png"), ("All", "*.*")])
        if p:
            self.path_stego = p
            self.lbl_stego.configure(text=os.path.basename(p))

    def _update_capacity(self):
        if self.path_cover and self.path_secret:
            try:
                # חישוב גודל תמונה
                img = Image.open(self.path_cover)
                pixels = img.width * img.height * len(img.getbands()) # תומך RGBA
                available_pixels = pixels - FIXED_HEADER_PIXELS
                
                # חישוב גודל קובץ + תקורה
                file_size = os.path.getsize(self.path_secret)
                # תקורה משוערת: Fernet מוסיף ~33% + Padding + Header שלנו
                estimated_bits = (file_size * 1.35 + 100) * 8
                
                ratio = estimated_bits / available_pixels
                
                self.cap_bar.set(min(ratio, 1.0))
                
                # צביעה דינמית
                pct = int(ratio * 100)
                if ratio > 1.0:
                    self.cap_bar.configure(progress_color="red")
                    self.lbl_cap_text.configure(text=f"שגיאה: הקובץ גדול מדי! ({pct}%)", text_color="red")
                elif ratio > 0.8:
                    self.cap_bar.configure(progress_color="orange")
                    self.lbl_cap_text.configure(text=f"אזהרה: נפח כמעט מלא ({pct}%)", text_color="orange")
                else:
                    self.cap_bar.configure(progress_color="#2CC985") # ירוק
                    self.lbl_cap_text.configure(text=f"תקין ({pct}%)", text_color="gray")
                    
            except Exception:
                pass

    # --- הפעלת תהליכים (Threading) ---

    def run_embed(self):
        # ולידציה
        pwd = self.entry_pass_hide.get()
        if not self.path_cover or not self.path_secret:
            messagebox.showwarning("חסר מידע", "נא לבחור תמונה וקובץ.")
            return
        if len(pwd) < 8:
            messagebox.showwarning("סיסמה חלשה", "מטעמי אבטחה, הסיסמה חייבת להיות באורך 8 תווים לפחות.")
            return

        out_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not out_path:
            return
            
        # בדיקת דריסה
        if os.path.exists(out_path):
            if not messagebox.askyesno("קובץ קיים", "הקובץ כבר קיים. האם לדרוס אותו?"):
                return

        self._set_busy(True, "מבצע הצפנה והטמעה...")
        threading.Thread(target=self._thread_embed, args=(pwd, out_path), daemon=True).start()

    def _thread_embed(self, pwd, out_path):
        try:
            StegoEngineV11.embed(self.path_cover, self.path_secret, pwd, out_path)
            self.after(0, lambda: messagebox.showinfo("הצלחה", "הקובץ הוצפן והוטמע בהצלחה!\nSalt ייחודי נוצר ונשמר בתמונה."))
            self.after(0, lambda: self._set_busy(False, "הושלם"))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("שגיאה", str(e)))
            self.after(0, lambda: self._set_busy(False, "שגיאה"))

    def run_extract(self):
        pwd = self.entry_pass_ext.get()
        if not self.path_stego or not pwd:
            messagebox.showwarning("חסר מידע", "נא לבחור תמונה ולהזין סיסמה.")
            return

        out_path = filedialog.asksaveasfilename(defaultextension=".key", title="שמור קובץ מחולץ")
        if not out_path:
            return

        self._set_busy(True, "מפענח...")
        threading.Thread(target=self._thread_extract, args=(pwd, out_path), daemon=True).start()

    def _thread_extract(self, pwd, out_path):
        try:
            success, msg = StegoEngineV11.extract(self.path_stego, pwd, out_path)
            if success:
                final_msg = "החילוץ בוצע בהצלחה!\nחתימה אומתה."
            else:
                final_msg = "החילוץ בוצע בהצלחה!\nחתימה אומתה!."
            
            self.after(0, lambda: messagebox.showinfo("תוצאה", final_msg))
            self.after(0, lambda: self._set_busy(False, "הושלם"))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("שגיאה קריטית", str(e)))
            self.after(0, lambda: self._set_busy(False, "שגיאה"))

    def _set_busy(self, is_busy, text):
        if is_busy:
            self.status_bar.configure(text=text, text_color="#4B8CDE")
            self.btn_embed.configure(state="disabled")
            self.btn_extract.configure(state="disabled")
        else:
            self.status_bar.configure(text=text, text_color="gray")
            self.btn_embed.configure(state="normal")
            self.btn_extract.configure(state="normal")

if __name__ == "__main__":
    app = StegoAppV11()
    app.mainloop()

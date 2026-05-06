import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import re
import hashlib

# --- CONFIGURACIÓN GLOBAL ---
TAMANO_BLOQUE = 190 
TAMANO_ENCRIPTADO = 256

carpeta_actual = ""
archivo_priv = ""
archivo_pub = ""
password_sesion = ""

def es_password_fuerte(psw):
    return len(psw) >= 8 and any(c.isupper() for c in psw) and re.search(r"[!@#$%^&*(),.? \":{}|<>_]", psw)

# --- LÓGICA DE SESIÓN ---

def validar_y_crear_entorno():
    global carpeta_actual, archivo_priv, archivo_pub, password_sesion
    password = entry_pass.get()
    if es_password_fuerte(password):
        password_sesion = password
        hash_id = hashlib.md5(password.encode()).hexdigest()[:8]
        carpeta_actual = f"Boveda_{hash_id}"
        archivo_priv = os.path.join(carpeta_actual, 'llave_privada.pem')
        archivo_pub = os.path.join(carpeta_actual, 'llave_publica.pem')

        if not os.path.exists(carpeta_actual):
            os.makedirs(carpeta_actual)
            messagebox.showinfo("Sistema", f"Bóveda creada: {carpeta_actual}")
        
        preparar_llaves(password)
        frame_login.pack_forget()
        lbl_status.config(text=f"Bóveda Activa: {carpeta_actual}", fg="darkgreen")
        frame_menu.pack(pady=20)
    else:
        messagebox.showerror("Error", "Contraseña débil.")

def preparar_llaves(password):
    if not os.path.exists(archivo_priv):
        keyPair = RSA.generate(2048)
        key_cifrada = keyPair.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")
        with open(archivo_priv, 'wb') as f: f.write(key_cifrada)
        with open(archivo_pub, 'wb') as f: f.write(keyPair.publickey().export_key())

# --- FUNCIONES DE CRIPTOGRAFÍA CON AUTO-DETECCIÓN ---

def solicitar_nombre_archivo():
    nombre = simpledialog.askstring("Guardar", "¿Nombre para el archivo .bin?")
    if not nombre: return None
    return os.path.join(carpeta_actual, nombre if nombre.endswith(".bin") else nombre + ".bin")

def encriptar_generico(datos_con_prefijo):
    ruta_salida = solicitar_nombre_archivo()
    if not ruta_salida: return
    try:
        pubKey = RSA.import_key(open(archivo_pub, 'rb').read())
        cipher = PKCS1_OAEP.new(pubKey)
        cifrado = b""
        for i in range(0, len(datos_con_prefijo), TAMANO_BLOQUE):
            cifrado += cipher.encrypt(datos_con_prefijo[i:i+TAMANO_BLOQUE])
        with open(ruta_salida, 'wb') as f: f.write(cifrado)
        messagebox.showinfo("Éxito", "Archivo cifrado con etiqueta de tipo.")
    except Exception as e:
        messagebox.showerror("Error", f"Error: {e}")

def encriptar_texto():
    msg = entry_texto.get()
    if msg:
        # Añadimos prefijo para identificar que es texto
        datos = ("TXT:" + msg).encode('utf-8')
        encriptar_generico(datos)

def encriptar_imagen():
    ruta = filedialog.askopenfilename()
    if not ruta: return
    with open(ruta, 'rb') as f:
        # Añadimos prefijo binario para identificar imagen
        datos = b"IMG:" + f.read()
    encriptar_generico(datos)

def encriptar_ubicacion():
    lat, lon = entry_lat.get(), entry_lon.get()
    if lat and lon:
        datos = (f"LOC:Latitud: {lat}, Longitud: {lon}").encode('utf-8')
        encriptar_generico(datos)

def descifrar_archivo():
    archivo = filedialog.askopenfilename(initialdir=carpeta_actual, filetypes=[("Archivos BIN", "*.bin")])
    if not archivo: return
    psw = simpledialog.askstring("Seguridad", "Contraseña:", show='*')
    if not psw: return

    try:
        with open(archivo_priv, 'rb') as f:
            privKey = RSA.import_key(f.read(), passphrase=psw)
        
        cipher = PKCS1_OAEP.new(privKey)
        datos_cifrados = open(archivo, 'rb').read()
        original = b""
        for i in range(0, len(datos_cifrados), TAMANO_ENCRIPTADO):
            original += cipher.decrypt(datos_cifrados[i:i+TAMANO_ENCRIPTADO])

        # --- LÓGICA DE DETECCIÓN AUTOMÁTICA ---
        if original.startswith(b"IMG:"):
            contenido_limpio = original[4:] # Quitamos el "IMG:"
            ruta_img = os.path.join(carpeta_actual, "AUTO_RECUPERADO.jpg")
            with open(ruta_img, 'wb') as f: f.write(contenido_limpio)
            messagebox.showinfo("Detección: IMAGEN", f"Se detectó una imagen.\nGuardada en: {ruta_img}")
        
        elif original.startswith(b"TXT:"):
            contenido_limpio = original[4:].decode('utf-8')
            messagebox.showinfo("Detección: TEXTO", f"Mensaje descifrado:\n{contenido_limpio}")
            
        elif original.startswith(b"LOC:"):
            contenido_limpio = original[4:].decode('utf-8')
            messagebox.showinfo("Detección: UBICACIÓN", f"Coordenadas detectadas:\n{contenido_limpio}")
        
        else:
            messagebox.showwarning("Aviso", "No se reconoció el tipo de dato, se mostrará como texto plano.")
            messagebox.showinfo("Resultado", original.decode('utf-8', errors='ignore'))
            
    except Exception:
        messagebox.showerror("Error", "Contraseña incorrecta o archivo incompatible.")

def logout():
    frame_menu.pack_forget()
    entry_pass.delete(0, tk.END)
    lbl_status.config(text="Inicie sesión", fg="black")
    frame_login.pack(pady=50)

# --- INTERFAZ ---
root = tk.Tk()
root.title("RSA Vault Smart-Detect")
root.geometry("450x650")

lbl_status = tk.Label(root, text="Inicie sesión", font=("Arial", 9)); lbl_status.pack(pady=5)
frame_login = tk.Frame(root); frame_login.pack(pady=50)
tk.Label(frame_login, text="CONTRASEÑA MAESTRA").pack()
entry_pass = tk.Entry(frame_login, show="*", width=30, justify='center'); entry_pass.pack(pady=10)
tk.Button(frame_login, text="Entrar", command=validar_y_crear_entorno, bg="#2ecc71", width=25).pack()

frame_menu = tk.Frame(root)
tk.Label(frame_menu, text="ENTRADA DE DATOS", font=("Arial", 12, "bold")).pack(pady=10)
entry_texto = tk.Entry(frame_menu, width=40); entry_texto.pack()
tk.Button(frame_menu, text="Guardar Texto", command=encriptar_texto, width=30).pack(pady=5)
tk.Button(frame_menu, text="Guardar Imagen", command=encriptar_imagen, width=30).pack(pady=10)
tk.Label(frame_menu, text="COORDENADAS:").pack()
frame_coords = tk.Frame(frame_menu); frame_coords.pack()
entry_lat = tk.Entry(frame_coords, width=15); entry_lat.pack(side=tk.LEFT)
entry_lon = tk.Entry(frame_coords, width=15); entry_lon.pack(side=tk.LEFT)
tk.Button(frame_menu, text="Guardar Ubicación", command=encriptar_ubicacion, width=30).pack(pady=5)
tk.Label(frame_menu, text="------------------------------------------").pack(pady=10)
tk.Button(frame_menu, text="DESCIFRAR ARCHIVO (Auto-Detect)", command=descifrar_archivo, bg="#3498db", fg="white", width=30, height=2).pack()
tk.Button(frame_menu, text="Cerrar Sesión", command=logout, fg="red").pack(pady=20)

root.mainloop()
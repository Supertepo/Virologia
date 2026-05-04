import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import re
# --- CONFIGURACIÓN RSA ---
TAMANO_BLOQUE = 214
TAMANO_ENCRIPTADO = 256
def validar_password():
    password = entry_pass.get()
    if len(password) >= 8 and any(c.isupper() for c in password) and re.search(r"[!@#$%^&*(),.? \":{}|<>_]",
password):
        frame_login.pack_forget()
        preparar_llaves()
        frame_menu.pack(pady=20)
    else:
        messagebox.showerror("Error", "Contraseña débil. Debe tener 8 caracteres, una Mayúscula y un Símbolo.")
def preparar_llaves():
    if not os.path.exists('rsa'):
        keyPair = RSA.generate(2048)
        with open('rsa', 'wb') as f: f.write(keyPair.export_key('PEM'))
    with open('rsa.pub', 'wb') as f: f.write(keyPair.publickey().export_key())

# --- FUNCIONES ---
def encriptar_texto():
    msg = entry_texto.get().encode('utf-8')
    if not msg: return
    pubKey = RSA.import_key(open('rsa.pub', 'rb').read())
    cipher = PKCS1_OAEP.new(pubKey)
    cifrado = b""
    for i in range(0, len(msg), TAMANO_BLOQUE):
        cifrado += cipher.encrypt(msg[i:i+TAMANO_BLOQUE])
    with open("texto_cifrado.bin", 'wb') as f: f.write(cifrado)
    messagebox.showinfo("OK", "Archivo generado: texto_cifrado.bin")
def encriptar_imagen():
    ruta = filedialog.askopenfilename()
    if not ruta: return
    with open(ruta, 'rb') as f: msg = f.read()
    pubKey = RSA.import_key(open('rsa.pub', 'rb').read())
    cipher = PKCS1_OAEP.new(pubKey)
    cifrado = b""
    for i in range(0, len(msg), TAMANO_BLOQUE):
        cifrado += cipher.encrypt(msg[i:i+TAMANO_BLOQUE])
    with open("imagen_cifrada.bin", 'wb') as f: f.write(cifrado)

messagebox.showinfo("OK", "Archivo generado: imagen_cifrada.bin")
def encriptar_ubicacion():
    lat = entry_lat.get()
    lon = entry_lon.get()
    msg = f"COORDENADAS -> Lat: {lat}, Lon: {lon}".encode('utf-8')
    pubKey = RSA.import_key(open('rsa.pub', 'rb').read())
    cipher = PKCS1_OAEP.new(pubKey)
    cifrado = b""
    for i in range(0, len(msg), TAMANO_BLOQUE):
        cifrado += cipher.encrypt(msg[i:i+TAMANO_BLOQUE])
    with open("ubicacion_cifrada.bin", 'wb') as f: f.write(cifrado)
    messagebox.showinfo("OK", "Archivo generado: ubicacion_cifrada.bin")

def descifrar_archivo():
    arch_cifrado = filedialog.askopenfilename(filetypes=[("Archivos BIN", "*.bin")])
    if not arch_cifrado: return
    try:
        privKey = RSA.import_key(open('rsa', 'rb').read())
        cipher = PKCS1_OAEP.new(privKey)
        datos_cifrados = open(arch_cifrado, 'rb').read()
        original = b""
        for i in range(0, len(datos_cifrados), TAMANO_ENCRIPTADO):
            original += cipher.decrypt(datos_cifrados[i:i+TAMANO_ENCRIPTADO])           
        if messagebox.askyesno("Tipo", "¿El original era imagen?"):
            with open("RECUPERADO_archivo.jpg", 'wb') as f: f.write(original)
            messagebox.showinfo("ÉXITO", "Guardado como RECUPERADO_archivo.jpg")
        else:
            messagebox.showinfo("CONTENIDO", original.decode('utf-8'))
    except:
        messagebox.showerror("ERROR", "No se pudo descifrar.")
# --- INTERFAZ ---
root = tk.Tk()
root.title("RSA 2.0")
root.geometry("400x500")
# Frame Login
frame_login = tk.Frame(root)
frame_login.pack(pady=20)
tk.Label(frame_login, text="CONTRASEÑA DE ACCESO:").pack()
entry_pass = tk.Entry(frame_login, show="*")
entry_pass.pack()
tk.Button(frame_login, text="Entrar", command=validar_password).pack(pady=10)
# Frame Menú (oculto al inicio)
frame_menu = tk.Frame(root)
tk.Label(frame_menu, text="SISTEMA RSA 2.0", font=("Arial", 12, "bold")).pack()
tk.Button(frame_menu, text="1. Encriptar Texto", width=30, command=encriptar_texto).pack(pady=5)
entry_texto = tk.Entry(frame_menu, width=30)
entry_texto.pack()
tk.Button(frame_menu, text="2. Encriptar Imagen", width=30, command=encriptar_imagen).pack(pady=20)
tk.Label(frame_menu, text="Latitud / Longitud:").pack()
entry_lat = tk.Entry(frame_menu, width=15); entry_lat.pack()
entry_lon = tk.Entry(frame_menu, width=15); entry_lon.pack()
tk.Button(frame_menu, text="3. Encriptar Ubicación", width=30, command=encriptar_ubicacion).pack(pady=5)
tk.Label(frame_menu, text="="*30).pack()
tk.Button(frame_menu, text="4. DESCIFRAR ARCHIVO .bin", width=30, bg="blue", fg="white",
command=descifrar_archivo).pack(pady=10)
tk.Button(frame_menu, text="5. SALIR", width=30, command=root.quit).pack()
root.mainloop()
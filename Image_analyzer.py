import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk, ExifTags, JpegImagePlugin
import logging
from datetime import datetime
import os

print(cv2.__version__)
print(Image.__version__)
print(np.__version__)

# Creazione del file di log con la data odierna
log_dir = r"C:\Users\Carlo\Desktop\Digital_forensics\Digital_Forensics_progetto\log"
os.makedirs(log_dir, exist_ok=True)
log_filename = datetime.now().strftime("log_%Y-%m-%d.txt")
log_file_path = os.path.join(log_dir, log_filename)

# Configurazione del logging
logging.basicConfig(filename=log_file_path, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_exif_data(image_path):
    try:
        image = Image.open(image_path)
        exif_data = {}
        for tag, value in image._getexif().items():
            tag_name = ExifTags.TAGS.get(tag, tag)
            exif_data[tag_name] = value
        return exif_data
    except Exception as e:
        messagebox.showerror("Error", f"Could not extract EXIF data: {e}")
        logging.error(f"Could not extract EXIF data: {e}")
        return None

def get_quantization_table(image_path):
    try:
        image = Image.open(image_path)
        if isinstance(image, JpegImagePlugin.JpegImageFile):
            return image.quantization
        else:
            messagebox.showinfo("Info", "Quantization tables are only available for JPEG images.")
            return None
    except Exception as e:
        messagebox.showerror("Error", f"Could not extract quantization tables: {e}")
        logging.error(f"Could not extract quantization tables: {e}")
        return None
    
    
def browse_file():
    logging.info("Browsing for a file...")
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
    if file_path:
        selected_file.set(file_path)
        logging.info(f"Selected file: {file_path}")
        display_image(file_path)
    else:
        logging.warning("No file was selected.")

def display_image(image_path):
    try:
        img = Image.open(image_path)
        img.thumbnail((400, 400))  # Ridimensiona per adattarsi all'area di visualizzazione
        tk_img = ImageTk.PhotoImage(img)
        image_label.create_image(0, 0, anchor=tk.NW, image=tk_img)
        image_label.image = tk_img
        logging.info("Image displayed successfully.")
    except Exception as e:
        logging.error(f"Error displaying image: {str(e)}")
        messagebox.showerror("Error", str(e))

def analyze_cloning_with_template_matching():
    file_path = selected_file.get()
    if not file_path:
        logging.warning("No file selected for analysis.")
        messagebox.showwarning("No file selected", "Please select an image file to analyze.")
        return

    try:
        logging.info(f"Starting cloning analysis on file: {file_path}")
        img = cv2.imread(file_path)
        max_dim = 1200
        h, w = img.shape[:2]
        if max(h, w) > max_dim:
            resize_factor = (max_dim * 0.6) / max(h, w)
            new_size = (int(w * resize_factor), int(h * resize_factor))
            img = cv2.resize(img, new_size)
        img_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        logging.debug("Image successfully converted to grayscale.")

        r = cv2.selectROI("Select Region", img)
        cv2.destroyAllWindows()
        
        if r == (0, 0, 0, 0):
            logging.warning("No valid region selected.")
            messagebox.showwarning("No selection", "Please select a valid region.")
            return
        
        logging.info(f"Selected region: {r}")
        
        x, y, w, h = map(int, r)
        template = img_gray[y:y+h, x:x+w]

        expand_ratio = 1.2
        ex = int(w * expand_ratio)
        ey = int(h * expand_ratio)
        ex = min(ex, img_gray.shape[1] - x)
        ey = min(ey, img_gray.shape[0] - y)
        
        mask = np.ones_like(img_gray, dtype=np.uint8)
        mask[max(0, y-int((ey-h)/2)):min(img_gray.shape[0], y+ey),
             max(0, x-int((ex-w)/2)):min(img_gray.shape[1], x+ex)] = 0

        logging.debug(f"Mask created with shape: {mask.shape}")

        res = cv2.matchTemplate(img_gray, template, cv2.TM_CCOEFF_NORMED)
        
        threshold = 0.8
        loc = np.where(res >= threshold)

        logging.info("Template matching completed.")
        logging.debug(f"Locations found: {loc}")

        img_output = img.copy()
        matches_found = False
        for pt in zip(*loc[::-1]):
            if not (x-int((ex-w)/2) <= pt[0] < x+ex and y-int((ey-h)/2) <= pt[1] < y+ey):
                cv2.rectangle(img_output, pt, (pt[0] + w, pt[1] + h), (0, 255, 0), 2)
                matches_found = True
                logging.info(f"Cloning detected at: {pt}")
            else:
                logging.debug(f"Ignored location at: {pt} as it overlaps with the excluded region")

        if matches_found:
            result_text.set("Cloning detected!")
            logging.info("Cloning detected!")

            # Mostra il risultato
            img_rgb = cv2.cvtColor(img_output, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(img_rgb)
            pil_img.thumbnail((400, 400))
            tk_img = ImageTk.PhotoImage(pil_img)
            image_label.create_image(0, 0, anchor=tk.NW, image=tk_img)
            image_label.image = tk_img

            # Salva l'immagine con le aree clonati evidenziate
            result_image_path = os.path.join(log_dir, f"cloning_analysis_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.jpg")
            cv2.imwrite(result_image_path, img_output)
            logging.info(f"Cloning analysis image saved to: {result_image_path}")
        else:
            result_text.set("No cloning detected.")
            logging.info("No cloning detected.")

    except Exception as e:
        logging.error(f"Error during cloning analysis: {str(e)}")
        result_text.set(f"Error: {str(e)}")


def process_exif():
    file_path = selected_file.get()
    if not file_path:
        messagebox.showwarning("No file selected", "Please select an image file to process.")
        return

    exif_data = get_exif_data(file_path)
    
    if isinstance(exif_data, str):
        explanation = "Failed to extract EXIF data."
        result_text.set(explanation)
        logging.info(f"EXIF Data: {explanation}")
    else:
        exif_text = "\n".join(f"{tag}: {value}" for tag, value in exif_data.items())
        explanation = "EXIF Data extracted successfully."
        result_text.set(f"{explanation}\n\n{exif_text}")
        logging.info(f"EXIF Data: {explanation}\n{exif_text}")

def process_quantization():
    file_path = selected_file.get()
    if not file_path:
        messagebox.showwarning("No file selected", "Please select an image file to process.")
        return

    qt_data = get_quantization_table(file_path)
    if qt_data is None:
        explanation = "Failed to extract quantization table or image is not a JPEG."
        result_text.set(explanation)
        logging.info(f"Quantization Table: {explanation}")
    else:
        qt_text = ""
        explanation = "Quantization tables extracted successfully."
        for table_index, table in qt_data.items():
            qt_text += f"Table {table_index}:\n"
            if isinstance(table, list):
                for i in range(0, len(table), 8):  # Mostra 8 valori per riga
                    row_values = table[i:i+8]
                    qt_text += " ".join(f"{value:4}" for value in row_values) + "\n"
            qt_text += "\n"
        
        result_text.set(f"{explanation}\n\n{qt_text}")
        logging.info(f"Quantization Table: {explanation}\n{qt_text}")


# Creazione della finestra principale
root = tk.Tk()
root.title("Image Cloning Detection with Template Matching")

# Variabili per la GUI
selected_file = tk.StringVar()
result_text = tk.StringVar()

# Sezione per scegliere il file
file_frame = tk.Frame(root)
file_frame.pack(padx=10, pady=5)

file_label = tk.Label(file_frame, text="Selected File:")
file_label.pack(side=tk.LEFT)

file_entry = tk.Entry(file_frame, textvariable=selected_file, width=50)
file_entry.pack(side=tk.LEFT, padx=5)

browse_button = tk.Button(file_frame, text="Browse", command=browse_file)
browse_button.pack(side=tk.LEFT)

# Area per visualizzare l'immagine
image_label = tk.Canvas(root, width=400, height=400)
image_label.pack(padx=10, pady=10)

# Pulsanti per elaborare l'immagine
process_exif_button = tk.Button(root, text="Elabora EXIF", command=process_exif)
process_exif_button.pack(pady=5)

process_quant_button = tk.Button(root, text="Elabora Quantization", command=process_quantization)
process_quant_button.pack(pady=5)

analyze_cloning_button = tk.Button(root, text="Analyze Cloning", command=analyze_cloning_with_template_matching)
analyze_cloning_button.pack(pady=5)

# Sezione per mostrare i risultati
result_label = tk.Label(root, text="Results:")
result_label.pack()

result_box = tk.Message(root, textvariable=result_text, width=600)
result_box.pack(padx=10, pady=5)

# Avvia la GUI
root.mainloop()

import subprocess
import platform
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk 
import json
import os
import re

import sv_ttk # Importa la libreria sv-ttk

# --- Backend Network Functions ---

def is_valid_ip(ip):
    """Controlla se la stringa fornita è un indirizzo IPv4 valido."""
    pattern = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return pattern.match(ip)

def is_admin():
    """Controlla se lo script è eseguito con privilegi di amministratore (solo Windows)."""
    if platform.system() == "Windows":
        try:
            temp_file = os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "test_admin_privs.tmp")
            with open(temp_file, "w") as f:
                f.write("test")
            os.remove(temp_file)
            return True
        except PermissionError:
            return False
        except Exception as e:
            print(f"Errore durante il controllo dei privilegi di amministratore: {e}")
            return False
    return True

def get_network_adapters():
    """
    Restituisce una lista dei nomi delle schede di rete su Windows.
    Versione più robusta per il parsing dell'output di netsh.
    """
    if platform.system() != "Windows":
        return []
    
    adapters = []
    try:
        command = 'netsh interface ipv4 show interfaces'
        # Usiamo encoding='cp850' o 'latin-1'. Prova uno o l'altro se hai problemi.
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True, encoding='cp850') 
        
        # Regex adattata per includere la colonna MTU e gestire la spaziatura variabile
        interface_pattern = re.compile(
            r'^\s*\d+\s+\d+\s+\d+\s+(?:connected|Connesso|disconnected|Disconnesso)\s+(.+)$', 
            re.IGNORECASE | re.MULTILINE
        )

        matches = interface_pattern.finditer(result.stdout)
        
        for match in matches:
            adapter_name_candidate = match.group(1).strip()
            if adapter_name_candidate and "Loopback Pseudo-Interface" not in adapter_name_candidate:
                adapters.append(adapter_name_candidate)
        
    except subprocess.CalledProcessError as e:
        print(f"Errore durante il recupero delle schede di rete: {e.stderr.strip()}")
        messagebox.showwarning("Errore Rilevamento Schede", 
                               f"Impossibile rilevare le schede di rete. Assicurati che netsh sia disponibile e di avere i permessi. Dettagli: {e.stderr.strip()}")
    except Exception as e:
        print(f"Errore inaspettato durante il recupero delle schede di rete: {e}")
        messagebox.showwarning("Errore Rilevamento Schede", 
                               f"Si è verificato un errore inaspettato durante il rilevamento delle schede: {e}")
    
    return adapters

def cambia_indirizzo_ip_ethernet(nome_scheda, nuovo_ip, subnet_mask, gateway, dns_primario=None, dns_secondario=None):
    """
    Cambia l'indirizzo IP, la subnet mask, il gateway e opzionalmente i server DNS
    di una scheda di rete Ethernet su Windows.
    Restituisce (True, messaggio_successo) o (False, messaggio_errore).
    """
    if platform.system() != "Windows":
        return False, "Questo script è progettato per funzionare solo su sistemi Windows."

    if not is_admin():
        return False, "Permesso negato. Esegui l'applicazione come AMMINISTRATORE."

    if not all(map(is_valid_ip, [nuovo_ip, subnet_mask, gateway])):
        return False, "Errore di validazione: Indirizzo IP, Subnet Mask o Gateway non validi."
    if dns_primario and not is_valid_ip(dns_primario):
        return False, "Errore di validazione: DNS Primario non valido."
    if dns_secondario and not is_valid_ip(dns_secondario):
        return False, "Errore di validazione: DNS Secondario non valido."

    try:
        comando_ip = f'netsh interface ipv4 set address name="{nome_scheda}" static {nuovo_ip} {subnet_mask} {gateway}'
        subprocess.run(comando_ip, shell=True, capture_output=True, text=True, check=True)

        subprocess.run(f'netsh interface ipv4 set dns name="{nome_scheda}" source=dhcp', shell=True, capture_output=True, text=True, check=False) 

        if dns_primario:
            comando_dns_primario = f'netsh interface ipv4 set dns name="{nome_scheda}" static {dns_primario} primary'
            subprocess.run(comando_dns_primario, shell=True, capture_output=True, text=True, check=True)
            
            if dns_secondario:
                comando_dns_secondario = f'netsh interface ipv4 add dns name="{nome_scheda}" {dns_secondario} index=2'
                subprocess.run(comando_dns_secondario, shell=True, capture_output=True, text=True, check=True)

        return True, f"Indirizzo IP impostato con successo per '{nome_scheda}' su {nuovo_ip}."

    except subprocess.CalledProcessError as e:
        return False, f"ERRORE: Impossibile cambiare le impostazioni IP. Dettagli: {e.stderr.strip()}"
    except Exception as e:
        return False, f"Si è verificato un errore inaspettato: {e}"

def ripristina_dhcp(nome_scheda):
    """
    Ripristina la configurazione DHCP per una scheda di rete su Windows.
    Restituisce (True, messaggio_successo) o (False, messaggio_errore).
    """
    if platform.system() != "Windows":
        return False, "Questo script è progettato per funzionare solo su sistemi Windows."

    if not is_admin():
        return False, "Permesso negato. Esegui l'applicazione come AMMINISTRATORE."

    try:
        comando_dhcp_ip = f'netsh interface ipv4 set address name="{nome_scheda}" source=dhcp'
        subprocess.run(comando_dhcp_ip, shell=True, capture_output=True, text=True, check=True)

        comando_dhcp_dns = f'netsh interface ipv4 set dns name="{nome_scheda}" source=dhcp'
        subprocess.run(comando_dhcp_dns, shell=True, capture_output=True, text=True, check=True)

        return True, f"Configurazione DHCP ripristinata con successo per '{nome_scheda}'."
    except subprocess.CalledProcessError as e:
        return False, f"ERRORE: Impossibile ripristinare DHCP. Dettagli: {e.stderr.strip()}"
    except Exception as e:
        return False, f"Si è verificato un errore inaspettato durante il ripristino DHCP: {e}"

# --- Gestione Profili (Salvataggio/Caricamento) ---
PROFILE_FILE = "network_profiles.json"

def load_profiles():
    """Carica i profili dal file JSON."""
    if os.path.exists(PROFILE_FILE):
        try:
            with open(PROFILE_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            messagebox.showwarning("Avviso", "Il file di profili è corrotto o vuoto. Verrà creato un nuovo file.")
            return {}
        except IOError as e:
            messagebox.showerror("Errore di Lettura", f"Impossibile leggere il file di profili: {e}")
            return {}
    return {}

def save_profiles(profiles):
    """Salva i profili nel file JSON."""
    try:
        with open(PROFILE_FILE, 'w') as f:
            json.dump(profiles, f, indent=4)
    except IOError as e:
        messagebox.showerror("Errore di Scrittura", f"Impossibile salvare i profili: {e}")

# --- Applicazione GUI ---
class NetworkConfiguratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Gestore Profili Rete")
        master.geometry("750x600")
        master.resizable(False, False)

        if not is_admin():
            messagebox.showerror("Errore Permessi", "Questa applicazione richiede privilegi di amministratore per funzionare correttamente. Esegui come amministratore e riprova.")
            master.destroy()
            return
        
        # --- Applica il tema sv-ttk per Windows 11 Fluent Design ---
        # NON esiste "system" in sv_ttk.set_theme(). Usiamo "light" o "dark".
        sv_ttk.set_theme("light") # Oppure "dark" per un tema scuro predefinito.
                                  # Per un toggle dinamico basato sul tema di sistema,
                                  # dovremmo implementare una logica più complessa.

        self.profiles = load_profiles()
        self.current_profile_name = None
        self.available_adapters = get_network_adapters()

        self.create_widgets()
        self.update_profile_list()

        if self.available_adapters:
            self.adapter_name_combobox.set(self.available_adapters[0])
        else:
            self.adapter_name_combobox.set("Nessuna Scheda Rilevata")
            self.display_message("Nessuna scheda di rete rilevata. Assicurati che siano attive e connesse.", "info")


    def create_widgets(self):
        profile_frame = ttk.LabelFrame(self.master, text="Profili Salvati", padding=5)
        profile_frame.pack(side="left", fill="both", expand=False, padx=10, pady=10)

        self.profile_listbox = tk.Listbox(profile_frame, height=15, width=30, exportselection=0)
        self.profile_listbox.pack(side="top", fill="both", expand=True)
        self.profile_listbox.bind('<<ListboxSelect>>', self.on_profile_select)

        profile_buttons_frame = ttk.Frame(profile_frame)
        profile_buttons_frame.pack(side="bottom", pady=5)

        ttk.Button(profile_buttons_frame, text="Aggiungi Nuovo", command=self.add_new_profile).pack(side="left", padx=2)
        ttk.Button(profile_buttons_frame, text="Elimina", command=self.delete_profile).pack(side="left", padx=2)


        settings_frame = ttk.LabelFrame(self.master, text="Impostazioni Correnti Profilo", padding=10)
        settings_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        ttk.Label(settings_frame, text="Nome Profilo:").grid(row=0, column=0, sticky="w", pady=2)
        self.profile_name_entry = ttk.Entry(settings_frame, width=35)
        self.profile_name_entry.grid(row=0, column=1, pady=2, padx=5)

        ttk.Label(settings_frame, text="Nome Scheda:").grid(row=1, column=0, sticky="w", pady=2)
        self.adapter_name_combobox = ttk.Combobox(settings_frame, values=self.available_adapters, state="readonly", width=33)
        self.adapter_name_combobox.grid(row=1, column=1, pady=2, padx=5)
        if self.available_adapters:
            self.adapter_name_combobox.set(self.available_adapters[0]) 
        else:
            self.adapter_name_combobox.set("Nessuna Scheda Rilevata")


        labels = ["Indirizzo IP:", "Subnet Mask:", "Gateway:", "DNS Primario:", "DNS Secondario:"]
        self.entries = {}
        default_values = {
            "Indirizzo IP:": "192.168.1.100",
            "Subnet Mask:": "255.255.255.0",
            "Gateway:": "192.168.1.1",
            "DNS Primario:": "8.8.8.8",
            "DNS Secondario:": "8.8.4.4"
        }

        for i, label_text in enumerate(labels):
            ttk.Label(settings_frame, text=label_text).grid(row=i+2, column=0, sticky="w", pady=2)
            ttk_entry = ttk.Entry(settings_frame, width=35)
            ttk_entry.grid(row=i+2, column=1, pady=2, padx=5)
            ttk_entry.insert(0, default_values[label_text])
            self.entries[label_text] = ttk_entry

        action_buttons_frame = ttk.Frame(settings_frame)
        action_buttons_frame.grid(row=len(labels)+2, column=0, columnspan=2, pady=10)

        ttk.Button(action_buttons_frame, text="Salva/Aggiorna Profilo", command=self.save_or_update_profile).pack(side="left", padx=5)
        ttk.Button(action_buttons_frame, text="Applica Profilo Selezionato", command=self.apply_selected_profile).pack(side="left", padx=5)
        ttk.Button(action_buttons_frame, text="Ripristina DHCP", command=self.restore_dhcp_action).pack(side="left", padx=5)

        self.output_text = tk.Text(self.master, height=8, width=70, wrap="word", state="disabled")
        self.output_text.pack(side="bottom", pady=10, padx=10, fill="x")
        self.output_text.tag_configure("error", foreground="red")
        self.output_text.tag_configure("success", foreground="green")
        self.output_text.tag_configure("info", foreground="blue")


    def display_message(self, message, msg_type="info"):
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, message)
        if msg_type == "error":
            self.output_text.tag_add("error", "1.0", tk.END)
        elif msg_type == "success":
            self.output_text.tag_add("success", "1.0", tk.END)
        elif msg_type == "info":
            self.output_text.tag_add("info", "1.0", tk.END)
        self.output_text.config(state="disabled")


    def update_profile_list(self):
        self.profile_listbox.delete(0, tk.END)
        for name in sorted(self.profiles.keys()):
            self.profile_listbox.insert(tk.END, name)

    def on_profile_select(self, event):
        selection = self.profile_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        profile_name = self.profile_listbox.get(index)
        self.current_profile_name = profile_name
        profile_data = self.profiles[profile_name]

        self.profile_name_entry.delete(0, tk.END)
        self.profile_name_entry.insert(0, profile_name)

        adapter_name_from_profile = profile_data.get("adapter_name", "")
        if adapter_name_from_profile in self.available_adapters:
            self.adapter_name_combobox.set(adapter_name_from_profile)
        elif self.available_adapters:
            self.adapter_name_combobox.set(self.available_adapters[0])
        else:
            self.adapter_name_combobox.set("Nessuna Scheda Rilevata")


        self.entries["Indirizzo IP:"].delete(0, tk.END)
        self.entries["Indirizzo IP:"].insert(0, profile_data.get("ip", ""))

        self.entries["Subnet Mask:"].delete(0, tk.END)
        self.entries["Subnet Mask:"].insert(0, profile_data.get("subnet", ""))

        self.entries["Gateway:"].delete(0, tk.END)
        self.entries["Gateway:"].insert(0, profile_data.get("gateway", ""))

        self.entries["DNS Primario:"].delete(0, tk.END)
        self.entries["DNS Primario:"].insert(0, profile_data.get("dns1", ""))

        self.entries["DNS Secondario:"].delete(0, tk.END)
        self.entries["DNS Secondario:"].insert(0, profile_data.get("dns2", ""))

        self.display_message(f"Profilo '{profile_name}' caricato. Ora puoi modificarlo o applicarlo.", "info")

    def clear_input_fields(self, include_profile_name=True):
        if include_profile_name:
            self.profile_name_entry.delete(0, tk.END)
        
        if self.available_adapters:
            self.adapter_name_combobox.set(self.available_adapters[0])
        else:
            self.adapter_name_combobox.set("Nessuna Scheda Rilevata")
        
        for entry in self.entries.values():
            entry.delete(0, tk.END)

    def add_new_profile(self):
        self.clear_input_fields(include_profile_name=True)
        self.entries["Indirizzo IP:"].insert(0, "192.168.1.100")
        self.entries["Subnet Mask:"].insert(0, "255.255.255.0")
        self.entries["Gateway:"].insert(0, "192.168.1.1")
        self.entries["DNS Primario:"].insert(0, "8.8.8.8")
        self.entries["DNS Secondario:"].insert(0, "8.8.4.4")

        self.profile_name_entry.focus_set()
        self.display_message("Inserisci il nome del nuovo profilo e compila i campi, poi clicca 'Salva/Aggiorna Profilo'.", "info")
        self.current_profile_name = None
        self.profile_listbox.selection_clear(0, tk.END)

    def save_or_update_profile(self):
        profile_name = self.profile_name_entry.get().strip()
        if not profile_name:
            messagebox.showwarning("Input Mancante", "Il nome del profilo non può essere vuoto.")
            return

        if profile_name in self.profiles and profile_name != self.current_profile_name:
            if not messagebox.askyesno("Conferma Sovrascrittura", f"Un profilo con il nome '{profile_name}' esiste già. Vuoi sovrascriverlo?"):
                return

        adapter_name = self.adapter_name_combobox.get().strip()
        if not adapter_name or adapter_name == "Nessuna Scheda Rilevata":
            messagebox.showwarning("Input Mancante", "Seleziona o digita il nome della scheda di rete.")
            return

        ip = self.entries["Indirizzo IP:"].get().strip()
        subnet = self.entries["Subnet Mask:"].get().strip()
        gateway = self.entries["Gateway:"].get().strip()
        dns1 = self.entries["DNS Primario:"].get().strip() or None
        dns2 = self.entries["DNS Secondario:"].get().strip() or None

        if not all(map(is_valid_ip, [ip, subnet, gateway])):
            messagebox.showwarning("Errore di Validazione", "Indirizzo IP, Subnet Mask o Gateway non sono in un formato valido.")
            return
        if dns1 and not is_valid_ip(dns1):
            messagebox.showwarning("Errore di Validazione", "DNS Primario non è in un formato valido.")
            return
        if dns2 and not is_valid_ip(dns2):
            messagebox.showwarning("Errore di Validazione", "DNS Secondario non è in un formato valido.")
            return

        profile_data = {
            "adapter_name": adapter_name,
            "ip": ip,
            "subnet": subnet,
            "gateway": gateway,
            "dns1": dns1,
            "dns2": dns2
        }

        self.profiles[profile_name] = profile_data
        save_profiles(self.profiles)
        self.update_profile_list()
        self.current_profile_name = profile_name
        
        self.profile_listbox.selection_clear(0, tk.END)
        try:
            idx = list(sorted(self.profiles.keys())).index(profile_name)
            self.profile_listbox.selection_set(idx)
            self.profile_listbox.activate(idx)
        except ValueError:
            pass 

        self.display_message(f"Profilo '{profile_name}' salvato/aggiornato con successo.", "success")


    def delete_profile(self):
        selection = self.profile_listbox.curselection()
        if not selection:
            messagebox.showwarning("Nessuna Selezione", "Seleziona un profilo da eliminare dalla lista.")
            return

        index = selection[0]
        profile_name = self.profile_listbox.get(index)

        if messagebox.askyesno("Conferma Eliminazione", f"Sei sicuro di voler eliminare il profilo '{profile_name}'?"):
            del self.profiles[profile_name]
            save_profiles(self.profiles)
            self.update_profile_list()
            self.clear_input_fields()
            self.display_message(f"Profilo '{profile_name}' eliminato.", "info")
            self.current_profile_name = None

    def apply_selected_profile(self):
        selection = self.profile_listbox.curselection()
        if not selection:
            messagebox.showwarning("Nessuna Selezione", "Seleziona un profilo dalla lista per applicarlo.")
            return

        index = selection[0]
        profile_name = self.profile_listbox.get(index)
        profile_data = self.profiles[profile_name]

        adapter_name = profile_data.get("adapter_name", "") 
        ip = profile_data.get("ip", "")
        subnet = profile_data.get("subnet", "")
        gateway = profile_data.get("gateway", "")
        dns1 = profile_data.get("dns1", None)
        dns2 = profile_data.get("dns2", None)

        if not all([adapter_name, ip, subnet, gateway]):
            messagebox.showwarning("Dati Mancanti", "Il profilo selezionato non ha tutti i dati di rete essenziali (nome scheda, IP, subnet, gateway).")
            return
        
        self.display_message(f"Applicando il profilo '{profile_name}' a '{adapter_name}'...", "info")
        success, message = cambia_indirizzo_ip_ethernet(adapter_name, ip, subnet, gateway, dns1, dns2)
        
        if success:
            self.display_message(message, "success")
            messagebox.showinfo("Successo", message)
        else:
            self.display_message(message, "error")
            messagebox.showerror("Errore", message)

    def restore_dhcp_action(self):
        adapter_name = self.adapter_name_combobox.get().strip()
        if not adapter_name or adapter_name == "Nessuna Scheda Rilevata":
            messagebox.showwarning("Input Mancante", "Seleziona o digita il nome della scheda di rete per ripristinare DHCP.")
            return
        
        self.display_message(f"Ripristinando DHCP per '{adapter_name}'...", "info")
        success, message = ripristina_dhcp(adapter_name)
        
        if success:
            self.display_message(message, "success")
            messagebox.showinfo("Successo", message)
            self.clear_input_fields(include_profile_name=True)
            self.profile_name_entry.insert(0, f"DHCP Attivo su {adapter_name}") 
            self.adapter_name_combobox.set(adapter_name)
            self.profile_listbox.selection_clear(0, tk.END)
            self.current_profile_name = None
        else:
            self.display_message(message, "error")
            messagebox.showerror("Errore", message)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkConfiguratorApp(root)
    root.mainloop()
# -*- coding: utf-8 -*-
"""
STONY-TECHNOLOGIE - Suite d'Audit Cybersecurite Locale
--------------------------------------------------------
Outil local, transparent et manuel : analyse, sur une periode choisie par
l'utilisateur, les journaux Windows et l'historique de navigation presents
sur CETTE machine, puis genere un rapport PDF + un export CSV complet.

Limite assumee : ceci n'est PAS un enregistreur de frappe / capteur d'ecran.
L'outil lit uniquement des journaux et bases deja presents sur le disque
(journaux Windows, bases d'historique des navigateurs, metadonnees de
fichiers). Il ne peut donc pas restituer une activite qui n'a laisse aucune
trace locale (navigation privee non journalisee, etc.).
"""

import os
import sys
import subprocess
import sqlite3
import datetime
import glob
import importlib.util
import traceback
import shutil
import tempfile
import ctypes
import threading
import uuid
import csv
import hashlib
import concurrent.futures
import socket
import getpass
import platform
import urllib.request

# =====================================================================
# 0. DROITS ADMINISTRATEUR (necessaires pour les journaux Windows)
# =====================================================================
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def request_admin_privileges():
    """Relance en administrateur. Si l'UAC est refusee, on continue SANS
    bloquer : seuls les journaux Windows seront indisponibles."""
    if sys.platform != "win32" or is_admin():
        return
    print("[*] Elevation des privileges Administrateur requise pour les journaux Windows...")
    params = " ".join(f'"{arg}"' for arg in sys.argv)  # quoting individuel (chemins avec espaces)
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        if int(ret) > 32:
            sys.exit(0)
        print("[-] Elevation refusee : l'audit continuera sans les journaux Windows.")
    except Exception as e:
        print(f"[-] Impossible de demander l'elevation : {e}")

request_admin_privileges()

# =====================================================================
# 1. DEPENDANCES (installation + garde-fou anti-boucle infinie)
# =====================================================================
RESTART_FLAG = "STONY_AUDIT_RESTART_COUNT"
MAX_RESTARTS = 1

def install_dependencies():
    dependencies = {
        "flask": "flask",
        "fpdf": "fpdf2",
        "matplotlib": "matplotlib",
        "webview": "pywebview",  # paquet pip = "pywebview", module importable = "webview"
    }
    missing = [pkg for mod, pkg in dependencies.items() if importlib.util.find_spec(mod) is None]
    if not missing:
        return

    restart_count = int(os.environ.get(RESTART_FLAG, "0"))
    if restart_count >= MAX_RESTARTS:
        print(f"[-] Modules introuvables apres installation : {missing}")
        print(f"    (python actuel : {sys.executable})")
        input("Appuyez sur Entree pour fermer...")
        sys.exit(1)

    for pkg in missing:
        print(f"[*] Installation du module requis : {pkg}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        except subprocess.CalledProcessError as e:
            print(f"[-] Echec de l'installation de {pkg} : {e}")
            input("Appuyez sur Entree pour fermer...")
            sys.exit(1)

    print("[+] Installation terminee. Redemarrage de l'application...")
    env = os.environ.copy()
    env[RESTART_FLAG] = str(restart_count + 1)
    subprocess.run([sys.executable] + sys.argv, env=env)
    sys.exit(0)

install_dependencies()

try:
    from flask import Flask, request, send_file, jsonify, redirect, url_for
    from fpdf import FPDF
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import webview
except Exception as e:
    print(f"\n[-] Erreur critique lors de l'importation des modules : {e}")
    input("Appuyez sur Entree pour fermer...")
    sys.exit(1)

LOGO_PATH = "stony_logo.png"
SECTION_PDF_CAP = 400  # lignes affichees par section dans le PDF (le CSV, lui, est TOUJOURS complet)

# =====================================================================
# 2. UTILITAIRES
# =====================================================================
def get_desktop_path():
    if sys.platform == "win32":
        try:
            res = subprocess.run(["powershell", "-Command", "[Environment]::GetFolderPath('Desktop')"],
                                  capture_output=True, text=True, timeout=15)
            desktop = res.stdout.strip()
            if desktop and os.path.exists(desktop):
                return desktop
        except Exception:
            pass
    return os.path.join(os.path.expanduser("~"), "Desktop")

def create_desktop_shortcut():
    if sys.platform != "win32":
        return
    try:
        desktop = get_desktop_path()
        shortcut_path = os.path.join(desktop, "STONY-TECHNOLOGIE Audit.lnk")
        if os.path.exists(shortcut_path):
            return
        script_path = os.path.abspath(sys.argv[0])
        python_exe = sys.executable
        ps_cmd = f"""
        $WScriptShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WScriptShell.CreateShortcut("{shortcut_path}")
        $Shortcut.TargetPath = "{python_exe}"
        $Shortcut.Arguments = '"{script_path}"'
        $Shortcut.WorkingDirectory = "{os.path.dirname(script_path)}"
        $Shortcut.Description = "STONY-TECHNOLOGIE - Suite d'Audit Cybersecurite"
        $Shortcut.Save()
        """
        subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=20)
        print("[+] Raccourci Bureau cree avec succes.")
    except Exception as e:
        print(f"[-] Erreur lors de la creation du raccourci : {e}")

create_desktop_shortcut()

def clean_text(text):
    if not text:
        return ""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")

def day_range_bounds(start_date, end_date):
    start = datetime.datetime.combine(start_date, datetime.time.min)
    end = datetime.datetime.combine(end_date, datetime.time.max)
    return start, end

def to_chrome_epoch(dt):
    """Datetime Python -> timestamp Chrome/Edge (microsecondes depuis 1601-01-01)."""
    return int((dt - datetime.datetime(1601, 1, 1)).total_seconds() * 1_000_000)

def to_unix_us(dt):
    return int(dt.timestamp() * 1_000_000)

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# =====================================================================
# 3. PDF (charte STONY-TECHNOLOGIE)
# =====================================================================
class StonyPDF(FPDF):
    def header(self):
        if os.path.exists(LOGO_PATH):
            self.image(LOGO_PATH, 10, 8, 30)
        self.set_font("Helvetica", 'B', 10)
        self.set_text_color(10, 37, 64)
        self.cell(0, 10, clean_text("STONY-TECHNOLOGIE - Division Cybersecurite & Audit"),
                  new_x="LMARGIN", new_y="NEXT", align="R")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", 'I', 8)
        self.set_text_color(0, 200, 150)
        self.cell(0, 10, clean_text(f"STONY-TECHNOLOGIE | Confidentiel - Page {self.page_no()}"), align="C")

# =====================================================================
# 4. JOURNAUX WINDOWS (Securite / Systeme / Application)
# =====================================================================
def extract_windows_log(start_date, end_date, log_name):
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    ps_script = f"""
    try {{
        $events = Get-WinEvent -FilterHashtable @{{LogName="{log_name}"; StartTime="{start_str} 00:00:00"; EndTime="{end_str} 23:59:59"}} -ErrorAction Stop
        foreach ($e in $events) {{
            $msg = $e.Message -replace '([\\r\\n])', ' '
            Write-Output "$($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) [ID:$($e.Id)] [$($e.LevelDisplayName)] $msg"
        }}
    }} catch {{
        Write-Output "AUCUN_EVENEMENT"
    }}
    """
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script],
                                 capture_output=True, text=True, encoding="utf-8", errors="ignore",
                                 timeout=300)
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        lines = [l for l in lines if l != "AUCUN_EVENEMENT"]
        if not lines:
            return [f"Aucun evenement '{log_name}' sur cette periode (ou acces restreint sans droits admin)."]
        return lines
    except subprocess.TimeoutExpired:
        return [f"Extraction du journal '{log_name}' interrompue (delai depasse - periode trop large)."]
    except Exception as e:
        return [f"Erreur extraction journal '{log_name}' : {e}"]

# =====================================================================
# 5. NAVIGATEURS - historique COMPLET (toutes les visites, pas la derniere)
# =====================================================================
def get_firefox_history_path():
    base_path = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
    if os.path.exists(base_path):
        profiles = glob.glob(os.path.join(base_path, "*.default-release")) + glob.glob(os.path.join(base_path, "*.default"))
        if profiles:
            return os.path.join(profiles[0], "places.sqlite")
    return ""

def _copy_locked_db(db_path):
    tmp = os.path.join(tempfile.gettempdir(), f"stony_{uuid.uuid4().hex}_{os.path.basename(db_path)}")
    shutil.copy2(db_path, tmp)
    return tmp

def extract_browser_history(db_path, start_date, end_date, firefox=False, label="Navigateur"):
    data = []
    if not db_path or not os.path.exists(db_path):
        return data
    start, end = day_range_bounds(start_date, end_date)
    tmp = None
    try:
        tmp = _copy_locked_db(db_path)
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        if firefox:
            lo, hi = to_unix_us(start), to_unix_us(end)
            cur.execute(
                "SELECT p.url, p.title, datetime(h.visit_date/1000000,'unixepoch','localtime') "
                "FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id "
                "WHERE h.visit_date BETWEEN ? AND ? ORDER BY h.visit_date",
                (lo, hi),
            )
        else:
            lo, hi = to_chrome_epoch(start), to_chrome_epoch(end)
            cur.execute(
                "SELECT u.url, u.title, datetime(v.visit_time/1000000-11644473600,'unixepoch','localtime') "
                "FROM visits v JOIN urls u ON v.url = u.id "
                "WHERE v.visit_time BETWEEN ? AND ? ORDER BY v.visit_time",
                (lo, hi),
            )
        for url, title, visit_time in cur.fetchall():
            data.append((url, title or "(sans titre)", visit_time, label))
        conn.close()
    except Exception as e:
        data.append((f"[Erreur lecture {label}: {e}]", "", "", label))
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return data

def extract_browser_downloads(db_path, start_date, end_date, label="Navigateur"):
    data = []
    if not db_path or not os.path.exists(db_path):
        return data
    start, end = day_range_bounds(start_date, end_date)
    lo, hi = to_chrome_epoch(start), to_chrome_epoch(end)
    tmp = None
    try:
        tmp = _copy_locked_db(db_path)
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute(
            "SELECT target_path, tab_url, datetime(start_time/1000000-11644473600,'unixepoch','localtime') "
            "FROM downloads WHERE start_time BETWEEN ? AND ? ORDER BY start_time",
            (lo, hi),
        )
        for path, src_url, dtime in cur.fetchall():
            data.append((path or "(chemin inconnu)", src_url or "", dtime, f"{label} - Telechargement"))
        conn.close()
    except Exception:
        pass
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return data

# =====================================================================
# 6. FICHIERS RECEMMENT OUVERTS + LOGICIELS INSTALLES
# =====================================================================
def extract_recent_files(start_date, end_date):
    data = []
    recent_dir = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Microsoft", "Windows", "Recent")
    if not os.path.exists(recent_dir):
        return data
    try:
        for fname in os.listdir(recent_dir):
            fpath = os.path.join(recent_dir, fname)
            try:
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(fpath))
                if start_date <= mtime.date() <= end_date:
                    data.append((fname, "", mtime.strftime("%Y-%m-%d %H:%M:%S"), "Fichier recent"))
            except OSError:
                continue
    except Exception:
        pass
    return data

def extract_installed_software(start_date, end_date):
    start_str = start_date.strftime("%Y%m%d")
    end_str = end_date.strftime("%Y%m%d")
    ps_script = f"""
    $paths = @(
        'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
        'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
    )
    Get-ItemProperty $paths -ErrorAction SilentlyContinue |
      Where-Object {{ $_.InstallDate -ge '{start_str}' -and $_.InstallDate -le '{end_str}' -and $_.DisplayName }} |
      ForEach-Object {{ Write-Output "$($_.DisplayName)|$($_.DisplayVersion)|$($_.InstallDate)" }}
    """
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_script],
                                 capture_output=True, text=True, timeout=60)
        out = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            name = parts[0] if len(parts) > 0 else line
            version = parts[1] if len(parts) > 1 else ""
            idate = parts[2] if len(parts) > 2 else ""
            idate_fmt = f"{idate[0:4]}-{idate[4:6]}-{idate[6:8]}" if len(idate) == 8 else idate
            out.append((f"{name} (v.{version})" if version else name, "", idate_fmt, "Logiciel installe"))
        return out
    except Exception:
        return []

# =====================================================================
# 6bis. IDENTITE REELLE DE LA MACHINE (aucune valeur par defaut : chaque
#       champ est interroge en direct ; en cas d'echec, on l'indique
#       explicitement au lieu d'afficher une valeur fictive)
# =====================================================================
def extract_system_network_info():
    data = []
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        data.append((socket.gethostname(), "", now, "Nom de la machine"))
    except Exception as e:
        data.append((f"Indisponible ({e})", "", now, "Nom de la machine"))

    try:
        data.append((getpass.getuser(), "", now, "Utilisateur Windows actuellement connecte"))
    except Exception as e:
        data.append((f"Indisponible ({e})", "", now, "Utilisateur Windows actuellement connecte"))

    try:
        data.append((platform.platform(), "", now, "Version du systeme d'exploitation"))
    except Exception as e:
        data.append((f"Indisponible ({e})", "", now, "Version du systeme d'exploitation"))

    # Adresses IP locales REELLEMENT actives sur cette machine (hors boucle locale)
    ps_ip = (
        "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } | "
        "ForEach-Object { Write-Output \"$($_.IPAddress)|$($_.InterfaceAlias)\" }"
    )
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_ip],
                                 capture_output=True, text=True, timeout=20)
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if lines:
            for line in lines:
                ip, _, iface = line.partition("|")
                data.append((ip, iface, now, "Adresse IP locale active"))
        else:
            data.append(("Aucune interface IPv4 active detectee", "", now, "Adresse IP locale active"))
    except Exception as e:
        data.append((f"Indisponible ({e})", "", now, "Adresse IP locale active"))

    # Adresses MAC REELLES des interfaces actives
    ps_mac = (
        "Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | "
        "ForEach-Object { Write-Output \"$($_.MacAddress)|$($_.Name)\" }"
    )
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-Command", ps_mac],
                                 capture_output=True, text=True, timeout=20)
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        for line in lines:
            mac, _, iface = line.partition("|")
            data.append((mac, iface, now, "Adresse MAC active"))
    except Exception as e:
        data.append((f"Indisponible ({e})", "", now, "Adresse MAC active"))

    # Adresse IP PUBLIQUE reelle (necessite une connexion Internet active ;
    # aucune valeur fictive n'est affichee si la requete echoue)
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
            public_ip = resp.read().decode().strip()
        data.append((public_ip, "", now, "Adresse IP publique (Internet)"))
    except Exception as e:
        data.append((f"Non disponible : pas de connexion Internet ou service injoignable ({e})",
                      "", now, "Adresse IP publique (Internet)"))

    return data

# =====================================================================
# 7. GRAPHIQUE
# =====================================================================
def generate_graph(counts_dict, filename):
    pairs = [(k, v) for k, v in counts_dict.items() if v > 0]
    if not pairs:
        return False
    labels = [f"{k} ({v})" for k, v in pairs]
    counts = [v for _, v in pairs]
    colors = ["#0A2540", "#13365C", "#1F4E79", "#00C896", "#00A37D", "#FF6B35", "#D9541F", "#8A2BE2", "#555555", "#0078C8"]
    plt.figure(figsize=(7, 4.5))
    wedges, _texts, autotexts = plt.pie(
        counts, autopct=lambda pct: f'{pct:.1f}%' if pct > 2 else '',
        startangle=140, colors=colors[:len(counts)], pctdistance=0.75,
        wedgeprops=dict(width=0.55, edgecolor='white', linewidth=2),
    )
    plt.setp(autotexts, size=8, weight="bold", color="white")
    plt.legend(wedges, labels, title="Flux audites", loc="center left", bbox_to_anchor=(0.98, 0.5), fontsize=8)
    plt.title("Repartition des evenements audites", fontsize=13, fontweight='bold', color="#0A2540", pad=10)
    plt.tight_layout()
    plt.savefig(filename, dpi=180, bbox_inches='tight')
    plt.close()
    return True

# =====================================================================
# 8. CONSTRUCTION DU PDF
# =====================================================================
def add_pdf_section(pdf, title, color, logs):
    pdf.add_page()
    pdf.set_font("Helvetica", 'B', 13)
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, clean_text(f"  {title}  ({len(logs)} element(s))"), new_x="LMARGIN", new_y="NEXT", fill=True)
    pdf.ln(3)
    pdf.set_font("Helvetica", '', 8.5)
    pdf.set_text_color(40, 40, 40)

    if not logs:
        pdf.multi_cell(0, 5, clean_text("Aucune donnee trouvee pour cette periode."))
        return

    for item in logs[:SECTION_PDF_CAP]:
        val1, val2, ts, _label = item
        v1 = val1 if len(val1) < 95 else val1[:92] + "..."
        v2 = str(val2) if len(str(val2)) < 75 else str(val2)[:72] + "..."
        if ts and v2:
            text_line = f"[{ts}] {v2}\n  -> {v1}"
        elif ts:
            text_line = f"[{ts}] {v1}"
        else:
            text_line = v1
        pdf.multi_cell(0, 4.3, clean_text(text_line))
        pdf.ln(1)

    if len(logs) > SECTION_PDF_CAP:
        pdf.ln(2)
        pdf.set_font("Helvetica", 'I', 8)
        pdf.set_text_color(200, 50, 50)
        pdf.multi_cell(0, 5, clean_text(
            f"{len(logs) - SECTION_PDF_CAP} element(s) supplementaire(s) non affiches ici (lisibilite du PDF). "
            f"L'integralite figure dans l'export CSV."
        ))

def generate_pdf(start_date, end_date, sections, totals, out_path, password=None):
    pdf = StonyPDF()
    pdf.add_page()
    pdf.ln(15)
    pdf.set_font("Helvetica", 'B', 22)
    pdf.set_text_color(10, 37, 64)
    pdf.cell(0, 15, clean_text("RAPPORT D'AUDIT CYBERSECURITE"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", 'B', 12)
    pdf.set_text_color(255, 107, 53)
    period = f"du {start_date.strftime('%d/%m/%Y')} au {end_date.strftime('%d/%m/%Y')}" \
        if start_date != end_date else f"le {start_date.strftime('%d/%m/%Y')}"
    pdf.cell(0, 10, clean_text(f"Perimetre analyse : {period}"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(10)

    pdf.set_fill_color(240, 244, 248)
    pdf.rect(10, 75, 190, 45, style='F')
    pdf.set_xy(15, 80)
    pdf.set_font("Helvetica", 'B', 11)
    pdf.set_text_color(10, 37, 64)
    pdf.cell(0, 6, clean_text("SYNTHESE DE L'AUDIT :"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(15)
    pdf.set_font("Helvetica", '', 9.5)
    summary = " | ".join(f"{k}: {v}" for k, v in totals.items())
    pdf.set_xy(15, 88)
    pdf.multi_cell(180, 5, clean_text(summary))
    pdf.ln(23)

    pdf.set_font("Helvetica", 'B', 14)
    pdf.set_text_color(10, 37, 64)
    pdf.cell(0, 10, clean_text("Sommaire"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", '', 11)
    pdf.set_text_color(50, 50, 50)
    pdf.multi_cell(0, 7, clean_text(
        "1. Identite machine & reseau (nom, IP locale/publique, MAC, OS - en direct)\n"
        "2. Journaux Windows - Securite\n3. Journaux Windows - Systeme\n4. Journaux Windows - Application\n"
        "5. Historique & Telechargements - Google Chrome\n6. Historique & Telechargements - Microsoft Edge\n"
        "7. Historique - Mozilla Firefox\n8. Fichiers recemment ouverts\n9. Logiciels installes\n"
        "10. Analyse graphique"
    ))

    for title, color, logs in sections:
        add_pdf_section(pdf, title, color, logs)

    pdf.add_page()
    pdf.set_font("Helvetica", 'B', 14)
    pdf.set_text_color(10, 37, 64)
    pdf.cell(0, 10, clean_text("Analyse graphique"), new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(10)
    graph_file = os.path.join(tempfile.gettempdir(), f"graph_{uuid.uuid4().hex}.png")
    if generate_graph(totals, graph_file):
        pdf.image(graph_file, x=15, y=50, w=180)
        os.remove(graph_file)
    else:
        pdf.set_font("Helvetica", '', 12)
        pdf.cell(0, 10, clean_text("Aucune donnee a representer."), new_x="LMARGIN", new_y="NEXT")

    if password:
        try:
            pdf.set_encryption(owner_password=password, user_password=password)
        except Exception as e:
            print(f"[-] Chiffrement du PDF indisponible sur cette version de fpdf2 : {e}")

    pdf.output(out_path)
    return out_path

def export_full_csv(sections, out_path):
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["Categorie", "Horodatage", "Titre / Detail", "URL / Chemin / Message"])
        for title, _color, logs in sections:
            for val1, val2, ts, label in logs:
                writer.writerow([label or title, ts, val2, val1])
    return out_path

def write_manifest(out_dir, date_tag, files):
    manifest_path = os.path.join(out_dir, f"Manifeste_Integrite_{date_tag}.txt")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write("STONY-TECHNOLOGIE - Manifeste d'integrite (SHA-256)\n")
        f.write(f"Genere le : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for fpath in files:
            if os.path.exists(fpath):
                f.write(f"{os.path.basename(fpath)}\n  SHA-256 : {sha256_of(fpath)}\n\n")
    return manifest_path

# =====================================================================
# 9. ORCHESTRATION DE L'AUDIT (extractions en parallele)
# =====================================================================
def run_full_audit(start_date, end_date, password=None, file_format="pdf"):
    chrome_hist = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History")
    edge_hist = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "History")
    firefox_hist = get_firefox_history_path()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        f_sec = ex.submit(extract_windows_log, start_date, end_date, "Security")
        f_sys = ex.submit(extract_windows_log, start_date, end_date, "System")
        f_app = ex.submit(extract_windows_log, start_date, end_date, "Application")
        f_chrome = ex.submit(extract_browser_history, chrome_hist, start_date, end_date, False, "Chrome")
        f_edge = ex.submit(extract_browser_history, edge_hist, start_date, end_date, False, "Edge")
        f_firefox = ex.submit(extract_browser_history, firefox_hist, start_date, end_date, True, "Firefox")
        f_chrome_dl = ex.submit(extract_browser_downloads, chrome_hist, start_date, end_date, "Chrome")
        f_edge_dl = ex.submit(extract_browser_downloads, edge_hist, start_date, end_date, "Edge")
        f_recent = ex.submit(extract_recent_files, start_date, end_date)
        f_soft = ex.submit(extract_installed_software, start_date, end_date)
        f_netinfo = ex.submit(extract_system_network_info)

        # extract_windows_log renvoie des chaines simples ; on les uniformise en
        # tuples (texte, "", "", label) pour que le PDF et le CSV n'aient qu'un
        # seul format a traiter.
        win_sec = [(line, "", "", "Windows - Securite") for line in f_sec.result()]
        win_sys = [(line, "", "", "Windows - Systeme") for line in f_sys.result()]
        win_app = [(line, "", "", "Windows - Application") for line in f_app.result()]
        chrome_logs = f_chrome.result() + f_chrome_dl.result()
        edge_logs = f_edge.result() + f_edge_dl.result()
        firefox_logs = f_firefox.result()
        recent_files = f_recent.result()
        installed_software = f_soft.result()
        netinfo = f_netinfo.result()

    sections = [
        ("Identite machine & reseau (en direct)", (0, 90, 60), netinfo),
        ("Journaux Windows - Securite", (10, 37, 64), win_sec),
        ("Journaux Windows - Systeme", (10, 37, 64), win_sys),
        ("Journaux Windows - Application", (10, 37, 64), win_app),
        ("Historique & Telechargements - Chrome", (0, 200, 150), chrome_logs),
        ("Historique & Telechargements - Edge", (255, 107, 53), edge_logs),
        ("Historique - Firefox", (128, 0, 128), firefox_logs),
        ("Fichiers recemment ouverts", (90, 90, 90), recent_files),
        ("Logiciels installes", (0, 120, 200), installed_software),
    ]
    totals = {title.split(" - ")[-1] if " - " in title else title: len(logs) for title, _c, logs in sections}

    out_dir = get_desktop_path()
    date_tag = start_date.strftime("%d-%m-%Y") if start_date == end_date \
        else f"{start_date.strftime('%d-%m-%Y')}_au_{end_date.strftime('%d-%m-%Y')}"

    pdf_path, csv_path = None, None
    generated_files = []

    if file_format == "csv":
        csv_path = os.path.join(out_dir, f"Rapport_Audit_Stony_{date_tag}.csv")
        export_full_csv(sections, csv_path)
        generated_files.append(csv_path)
    else:
        pdf_path = os.path.join(out_dir, f"Rapport_Audit_Stony_{date_tag}.pdf")
        generate_pdf(start_date, end_date, sections, totals, pdf_path, password=password)
        generated_files.append(pdf_path)

    manifest_path = write_manifest(out_dir, date_tag, generated_files)

    return pdf_path, csv_path, manifest_path, totals

# =====================================================================
# 10. TACHES EN ARRIERE-PLAN (jamais de blocage de l'interface)
# =====================================================================
JOBS = {}
JOBS_LOCK = threading.Lock()

def background_audit(job_id, start_date, end_date, password, file_format):
    try:
        pdf_path, csv_path, manifest_path, totals = run_full_audit(
            start_date, end_date, password=password, file_format=file_format
        )
        with JOBS_LOCK:
            JOBS[job_id] = {"status": "done", "pdf": pdf_path, "csv": csv_path,
                             "manifest": manifest_path, "totals": totals, "format": file_format}
    except Exception:
        err = traceback.format_exc()
        print(err)
        with JOBS_LOCK:
            JOBS[job_id] = {"status": "error", "error": err}

# =====================================================================
# 11. INTERFACE WEB (Flask)
# =====================================================================
app = Flask(__name__)

CLOSE_LINK = ('<a href="/exit" style="position:fixed; top:15px; right:15px; background:#e53e3e; '
              'color:white; padding:8px 16px; border-radius:6px; font-weight:bold; text-decoration:none; '
              'font-size:13px;">Fermer</a>')

@app.route("/exit")
def exit_app():
    threading.Thread(target=lambda: os._exit(0), daemon=True).start()
    return "Fermeture..."

@app.route("/", methods=["GET"])
def index():
    return f'''
    <html><head><title>STONY-TECHNOLOGIE - Suite d'Audit</title></head>
    <body style="font-family:'Segoe UI',Tahoma,sans-serif; text-align:center; background:#F4F7F6; padding-top:40px; margin:0;">
        {CLOSE_LINK}
        <h1 style="color:#0A2540; margin-bottom:5px; font-size:28px;">STONY-TECHNOLOGIE</h1>
        <p style="color:#00C896; font-weight:bold; margin-top:0; font-size:15px; letter-spacing:1px;">SUITE PROFESSIONNELLE D'AUDIT CYBERSECURITE</p>
        <div style="background:white; display:inline-block; padding:35px; border-radius:12px; box-shadow:0px 8px 20px rgba(10,37,64,0.08); margin-top:15px; width:440px; box-sizing:border-box; text-align:left;">
            <form method="POST" action="/audit">
                <label style="font-weight:600; color:#0A2540; font-size:13px; display:block; margin-bottom:6px;">Date de debut :</label>
                <input type="date" name="date_debut" required style="padding:10px; margin-bottom:12px; width:100%; text-align:center; font-size:15px; border:2px solid #e1e4e8; border-radius:6px; box-sizing:border-box;">

                <label style="font-weight:600; color:#0A2540; font-size:13px; display:block; margin-bottom:6px;">Date de fin :</label>
                <input type="date" name="date_fin" required style="padding:10px; margin-bottom:12px; width:100%; text-align:center; font-size:15px; border:2px solid #e1e4e8; border-radius:6px; box-sizing:border-box;">

                <label style="font-weight:600; color:#0A2540; font-size:13px; display:block; margin-bottom:6px;">Format du rapport :</label>
                <select name="format" style="padding:10px; margin-bottom:12px; width:100%; font-size:14px; border:2px solid #e1e4e8; border-radius:6px; box-sizing:border-box; background:white;">
                    <option value="pdf">Rapport PDF professionnel</option>
                    <option value="csv">Tableur Excel (CSV)</option>
                </select>

                <label style="font-weight:600; color:#0A2540; font-size:13px; display:block; margin-bottom:6px;">Proteger le PDF par mot de passe (facultatif, ignore si Excel) :</label>
                <input type="password" name="password" placeholder="Laisser vide = pas de protection" style="padding:10px; margin-bottom:18px; width:100%; font-size:14px; border:2px solid #e1e4e8; border-radius:6px; box-sizing:border-box;">

                <button type="submit" style="background:#00C896; color:white; padding:13px; border:none; border-radius:6px; font-weight:bold; font-size:15px; cursor:pointer; width:100%;">Lancer l'audit complet</button>
            </form>
        </div>
        <p style="color:#999; font-size:11px; max-width:440px; margin:15px auto 0;">PDF + export CSV complet + manifeste d'integrite SHA-256 generes sur le Bureau. Les droits administrateur sont necessaires pour les journaux Windows.</p>
    </body></html>
    '''

@app.route("/audit", methods=["POST"])
def start_audit():
    start_str = request.form.get("date_debut")
    end_str = request.form.get("date_fin")
    password = request.form.get("password") or None  # vide => pas de protection
    file_format = request.form.get("format", "pdf")
    if file_format not in ("pdf", "csv"):
        file_format = "pdf"
    try:
        start_date = datetime.datetime.strptime(start_str, "%Y-%m-%d").date()
        end_date = datetime.datetime.strptime(end_str, "%Y-%m-%d").date()
    except Exception:
        return "<h3 style='color:red; text-align:center;'>Format de date invalide.</h3><br><center><a href='/'>Retour</a></center>"
    if start_date > end_date:
        return "<h3 style='color:red; text-align:center;'>La date de debut doit preceder la date de fin.</h3><br><center><a href='/'>Retour</a></center>"

    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {"status": "running"}
    threading.Thread(target=background_audit, args=(job_id, start_date, end_date, password, file_format), daemon=True).start()
    return redirect(url_for("progress", job_id=job_id))

@app.route("/progress/<job_id>")
def progress(job_id):
    return f'''
    <html><head><title>Audit en cours...</title>
    <script>
      async function poll() {{
        const r = await fetch("/status/{job_id}");
        const data = await r.json();
        if (data.status === "done") {{ window.location = "/result/{job_id}"; }}
        else if (data.status === "error") {{
            document.getElementById("err").style.display = "block";
            document.getElementById("errtxt").innerText = data.error;
        }} else {{ setTimeout(poll, 1000); }}
      }}
      window.onload = poll;
    </script></head>
    <body style="font-family:Arial; text-align:center; background:#F4F7F6; padding-top:80px; margin:0;">
      {CLOSE_LINK}
      <div style="background:white; width:440px; margin:auto; padding:50px 40px; border-radius:12px; box-shadow:0px 8px 20px rgba(10,37,64,0.08);">
        <h2 style="color:#0A2540; margin-top:0;">Audit en cours...</h2>
        <p style="color:#666; font-size:13px;">Extraction en parallele des journaux systeme et des navigateurs. L'interface reste reactive.</p>
        <div style="font-size:35px; margin-top:20px;">&#9889;</div>
        <div id="err" style="display:none; margin-top:20px; text-align:left; background:#fff5f5; border:1px solid #feb2b2; padding:10px; border-radius:6px;">
          <b>Erreur :</b><pre id="errtxt" style="white-space:pre-wrap; font-size:10px;"></pre>
          <a href="/">Retour</a>
        </div>
      </div>
    </body></html>
    '''

@app.route("/status/<job_id>")
def status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id, {"status": "error", "error": "Tache introuvable"})
    return jsonify(job)

@app.route("/result/<job_id>")
def result(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or job.get("status") != "done":
        return redirect(url_for("index"))
    totals_html = "<br>".join(f"{k} : <b>{v}</b>" for k, v in job["totals"].items())
    main_path = job.get("pdf") or job.get("csv")
    main_kind = "pdf" if job.get("pdf") else "csv"
    main_label = "Telecharger le PDF" if main_kind == "pdf" else "Telecharger le CSV"
    return f'''
    <html><body style="font-family:Arial; text-align:center; background:#F4F7F6; padding-top:40px; margin:0;">
      {CLOSE_LINK}
      <div style="background:white; max-width:560px; margin:auto; padding:40px; border-radius:10px; box-shadow:0px 4px 15px rgba(0,0,0,0.1);">
        <h2 style="color:#00C896; margin-top:0;">Audit termine avec succes !</h2>
        <p style="color:#555; font-size:13px; text-align:left;">{totals_html}</p>
        <p style="color:#0A2540; font-weight:bold; background:#f8f9fa; padding:10px; border-radius:6px; font-size:12px; word-break:break-all;">{main_path}</p>
        <a href="/download/{job_id}/{main_kind}" style="background:#0A2540; color:white; padding:12px 18px; text-decoration:none; border-radius:6px; font-weight:bold; display:inline-block; margin:4px; font-size:13px;">{main_label}</a>
        <a href="/download/{job_id}/manifest" style="background:#999; color:white; padding:12px 18px; text-decoration:none; border-radius:6px; font-weight:bold; display:inline-block; margin:4px; font-size:13px;">Manifeste SHA-256</a>
        <br><a href="/" style="display:inline-block; margin-top:15px; color:#0A2540; font-size:13px;">Effectuer un autre audit</a>
      </div>
    </body></html>
    '''

@app.route("/download/<job_id>/<kind>")
def download(job_id, kind):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job or job.get("status") != "done":
        return redirect(url_for("index"))
    path = {"pdf": job["pdf"], "csv": job["csv"], "manifest": job["manifest"]}.get(kind)
    if not path:
        return redirect(url_for("index"))
    return send_file(path, as_attachment=True)

# =====================================================================
# 12. LANCEMENT
# =====================================================================
if __name__ == "__main__":
    print("[*] Lancement du serveur local STONY-TECHNOLOGIE...")
    threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=5151, threaded=True, use_reloader=False),
        daemon=True,
    ).start()
    window = webview.create_window("STONY-TECHNOLOGIE Suite d'Audit", "http://127.0.0.1:5151",
                                    width=920, height=700)
    webview.start()
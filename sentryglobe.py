import os
import sys
import json
import socket
import urllib.parse
import threading
import webbrowser
import requests
from flask import Flask, jsonify, request, render_template_string

# Try to import Pillow for real Python EXIF extraction
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

app = Flask(__name__)


def resolve_host_to_ip(target):
    """Resolves a hostname/domain or returns the IP as-is."""
    try:
        # Clean URL if user entered one
        parsed = urllib.parse.urlparse(target)
        host = parsed.netloc or parsed.path
        if ":" in host:
            host = host.split(":")[0]
        return socket.gethostbyname(host)
    except Exception:
        return target

def extract_gps_metadata(file_stream):
    """Extracts real GPS coordinates from uploaded JPEG using Pillow."""
    if not HAS_PILLOW:
        return None
    try:
        img = Image.open(file_stream)
        exif_data = img._getexif()
        if not exif_data:
            return None
        
        gps_info = {}
        for tag, value in exif_data.items():
            decoded = TAGS.get(tag, tag)
            if decoded == "GPSInfo":
                for g_tag in value:
                    g_decoded = GPSTAGS.get(g_tag, g_tag)
                    gps_info[g_decoded] = value[g_tag]
        
        if "GPSLatitude" in gps_info and "GPSLongitude" in gps_info:
            lat = gps_info["GPSLatitude"]
            lat_ref = gps_info.get("GPSLatitudeRef", "N")
            lon = gps_info["GPSLongitude"]
            lon_ref = gps_info.get("GPSLongitudeRef", "E")

            # Convert rationals to floats
            lat_deg = float(lat[0]) + float(lat[1])/60.0 + float(lat[2])/3600.0
            if lat_ref == "S":
                lat_deg = -lat_deg
            
            lon_deg = float(lon[0]) + float(lon[1])/60.0 + float(lon[2])/3600.0
            if lon_ref == "W":
                lon_deg = -lon_deg

            return {"latitude": lat_deg, "longitude": lon_deg}
    except Exception as e:
        print(f"Error reading EXIF data: {e}")
    return None

def verify_username_existence(username):
    """Actively probes target platforms to verify if username profiles exist."""
    targets = {
        "github": f"https://github.com/{username}",
        "twitter": f"https://twitter.com/{username}",
        "reddit": f"https://www.reddit.com/user/{username}",
        "tiktok": f"https://www.tiktok.com/@{username}"
    }
    results = {}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    for platform, url in targets.items():
        try:
            # Execute real network probe
            response = requests.get(url, headers=headers, timeout=3.5)
            # 200 OK generally means user profile is occupied
            results[platform] = {
                "exists": response.status_code == 200,
                "url": url
            }
        except Exception:
            results[platform] = {
                "exists": False,
                "url": url
            }
    return results


@app.route("/")
def index():
    """Serves the primary high-performance front-end console."""
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/trace_ip", methods=["POST"])
def api_trace_ip():
    """OSINT endpoint to resolve hostnames and fetch secure geolocation metadata."""
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target specified"}), 400
    
    # Resolve domain to physical IP Address
    resolved_ip = resolve_host_to_ip(target)
    
    try:
        # Fetch secure geolocation from SSL service
        res = requests.get(f"https://ipapi.co/{resolved_ip}/json/", timeout=5)
        geo_data = res.json()
        return jsonify(geo_data)
    except Exception as e:
        return jsonify({"error": f"Failed to connect to geolocation services: {str(e)}"}), 500

@app.route("/api/exif_parse", methods=["POST"])
def api_exif_parse():
    """Processes forensic image upload and extracts geographic coordinates."""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if not HAS_PILLOW:
        return jsonify({"error": "Pillow is not installed on this Python host server."}), 500
    
    gps_coords = extract_gps_metadata(file.stream)
    if gps_coords:
        return jsonify(gps_coords)
    return jsonify({"error": "No valid GPS metadata found in the EXIF directory."}), 404

@app.route("/api/recon_username", methods=["POST"])
def api_recon_username():
    """Runs a live network reconnaissance sweep on a specific handle."""
    data = request.json or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "Username not specified"}), 400
    
    scan_results = verify_username_existence(username)
    return jsonify(scan_results)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es" class="h-full select-none">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>SentryGlobe OSINT & Tactical Monitor v4.5</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500;700&display=swap');
        
        body {
            font-family: 'Inter', sans-serif;
            background-color: #09090b;
        }

        .font-mono-tactical {
            font-family: 'JetBrains Mono', monospace;
        }

        ::-webkit-scrollbar {
            width: 3px;
            height: 3px;
        }
        ::-webkit-scrollbar-track {
            background: #09090b;
        }
        ::-webkit-scrollbar-thumb {
            background: #27272a;
            border-radius: 1px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #3f3f46;
        }

        .panel-transition {
            transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.3s ease;
            will-change: transform, opacity;
        }

        .radar-ping-node::after {
            content: '';
            position: absolute;
            width: 14px;
            height: 14px;
            border: 1px solid var(--ping-color, #06b6d4);
            border-radius: 50%;
            top: -3px;
            left: -3px;
            opacity: 0.8;
        }

        @keyframes loading-slide {
            0% { transform: translate3d(-100%, 0, 0); }
            100% { transform: translate3d(100%, 0, 0); }
        }
        .animate-infinite-loading {
            animation: loading-slide 1.5s infinite linear;
        }

        .crt-green-filter {
            filter: sepia(1) hue-rotate(90deg) saturate(7) brightness(0.7) contrast(1.8) invert(0.05);
            transition: filter 0.5s ease;
        }
        .no-filter {
            filter: none;
            transition: filter 0.5s ease;
        }

        /* CRT TERMINAL STYLE BASED ON image_9271a8.jpg */
        .crt-terminal {
            background: radial-gradient(circle, #051605 0%, #010501 100%);
            border: 2px solid #005a00;
            box-shadow: inset 0 0 15px rgba(0, 90, 0, 0.8), 0 0 10px rgba(0, 90, 0, 0.5);
            position: relative;
            overflow: hidden;
        }
        .crt-terminal::before {
            content: " ";
            display: block;
            position: absolute;
            top: 0; left: 0; bottom: 0; right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.03));
            background-size: 100% 3px, 3px 100%;
            z-index: 5;
            pointer-events: none;
        }
        .crt-glow {
            color: #00ff00;
            text-shadow: 0 0 4px rgba(0, 255, 0, 0.7);
        }
        .crt-grid-line {
            stroke: rgba(0, 255, 0, 0.2);
            stroke-width: 0.5;
        }
        .crt-coastline {
            fill: none;
            stroke: #00ff00;
            stroke-width: 0.8;
            stroke-linejoin: round;
            filter: drop-shadow(0px 0px 1px rgba(0,255,0,0.8));
        }

        @keyframes crt-blink {
            0%, 49% { opacity: 1; }
            50%, 100% { opacity: 0; }
        }
        .crt-cursor {
            display: inline-block;
            width: 5px;
            height: 10px;
            background-color: #00ff00;
            animation: crt-blink 1s infinite;
        }
    </style>
</head>
<body class="h-full w-full bg-[#09090b] text-zinc-100 flex flex-col overflow-hidden">

    <header class="h-12 border-b border-zinc-800/80 bg-[#09090b] flex items-center justify-between px-4 shrink-0 z-20">
        <div class="flex items-center gap-3">
            <div class="relative flex items-center justify-center w-7 h-7 rounded border border-cyan-500/30 bg-cyan-950/10">
                <i class="fa-solid fa-satellite-dish text-cyan-400 text-xs"></i>
            </div>
            <div>
                <h1 class="text-xs font-semibold tracking-wider text-zinc-200">SENTRYGLOBE <span class="text-cyan-400 font-bold">OSINT</span></h1>
                <p class="text-[9px] text-zinc-500 font-mono-tactical hidden sm:block">SISTEMA INTEGRADO DE TELEMETRÍA GLOBAL & MONITOREO DE FUENTES ABIERTAS</p>
            </div>
        </div>

        <div class="flex items-center gap-4 text-[10px] font-mono-tactical">
            <div class="hidden md:flex items-center gap-2 border-r border-zinc-800 pr-4">
                <span class="text-zinc-600">PYTHON BACKEND:</span>
                <span class="text-emerald-500 font-medium">CONECTADO</span>
            </div>
            <div class="hidden sm:flex items-center gap-2">
                <i class="fa-regular fa-clock text-cyan-500"></i>
                <span id="utc-clock" class="text-zinc-400">00:00:00 UTC</span>
            </div>
            <div class="relative flex items-center gap-1.5 bg-zinc-900 border border-zinc-800 rounded px-2 py-0.5 max-w-[160px] sm:max-w-[200px]">
                <i class="fa-solid fa-key text-[9px] text-amber-500"></i>
                <input type="password" id="gemma-key" placeholder="Gemma API Key (Opcional)" class="bg-transparent border-none text-[9px] outline-none text-zinc-200 placeholder-zinc-600 w-24 sm:w-32">
                <button onclick="toggleKeyVisibility()" class="text-zinc-500 hover:text-zinc-300 px-0.5">
                    <i class="fa-regular fa-eye text-[9px]" id="key-eye"></i>
                </button>
            </div>
        </div>
    </header>

    <div class="flex-1 flex overflow-hidden relative">

        <!-- LEFT SIDEBAR -->
        <div id="left-sidebar" class="panel-transition w-80 sm:w-96 border-r border-zinc-800 bg-[#09090b]/98 flex flex-col h-full shrink-0 z-30 relative shadow-xl">
            <!-- Tabs selection bar -->
            <div class="flex border-b border-zinc-800 bg-[#0c0c0e] text-center text-[10px]">
                <button onclick="switchLeftTab('console')" id="btn-tab-console" class="flex-1 py-3 px-1 border-b-2 border-cyan-500 text-cyan-400 font-semibold tracking-wider transition">
                    <i class="fa-solid fa-terminal mr-1"></i>CONSOLA
                </button>
                <button onclick="switchLeftTab('osint')" id="btn-tab-osint" class="flex-1 py-3 px-1 border-b-2 border-transparent text-zinc-500 font-semibold tracking-wider hover:bg-zinc-900/40 transition">
                    <i class="fa-solid fa-user-secret mr-1"></i>OSINT TOOLKIT
                </button>
                <button onclick="switchLeftTab('gemma')" id="btn-tab-gemma" class="flex-1 py-3 px-1 border-b-2 border-transparent text-zinc-500 font-semibold tracking-wider hover:bg-zinc-900/40 transition">
                    <i class="fa-solid fa-brain mr-1"></i>GEMMA AI
                </button>
            </div>

            <!-- Tab Contents -->
            <div class="flex-1 overflow-y-auto p-3.5 space-y-4 text-xs">
                
                <!-- TAB 1: CONSOLE -->
                <div id="tab-content-console" class="space-y-4">
                    <!-- Dynamic details populated depending on Map View Style -->
                    <div id="dynamic-console-section" class="space-y-3"></div>

                    <!-- Telemetry Network Graph -->
                    <div class="border border-zinc-800 bg-zinc-900/20 rounded-md p-3 space-y-3">
                        <span class="text-[9px] text-zinc-500 block font-semibold tracking-wider uppercase">Carga de Red del Sensor</span>
                        <div class="h-16 relative">
                            <canvas id="telemetry-chart"></canvas>
                        </div>
                        <div class="grid grid-cols-2 gap-2 text-[10px] text-zinc-400 pt-1 font-mono-tactical">
                            <div>Enlace Satelital: <span class="text-cyan-400" id="sat-status">100%</span></div>
                            <div>Ancho de Banda: <span class="text-cyan-400" id="packet-status">842 kb/s</span></div>
                        </div>
                    </div>

                    <!-- Terminal log list -->
                    <div class="border border-zinc-800 bg-zinc-950 rounded-md p-2.5 font-mono-tactical flex flex-col h-32">
                        <span class="text-[9px] text-zinc-500 mb-1.5 block">BITÁCORA DE SISTEMA:</span>
                        <div id="log-terminal" class="flex-1 overflow-y-auto text-[9px] text-emerald-500/90 space-y-1">
                            <div>[00:00:01] Iniciando SentryGlobe Python Server...</div>
                            <div>[00:00:02] Localizando Estación Base Local...</div>
                        </div>
                    </div>
                </div>

                <!-- TAB 2: OSINT TOOLKIT -->
                <div id="tab-content-osint" class="hidden space-y-4">
                    <!-- IP Tracker -->
                    <div class="border border-zinc-800 bg-zinc-900/20 rounded-md p-3 space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-[10px] font-semibold text-cyan-400 uppercase"><i class="fa-solid fa-globe mr-1"></i>Rastreador IP / Dominio</span>
                            <span class="text-[8px] bg-emerald-950/40 text-emerald-400 px-1.5 py-0.2 rounded font-semibold font-mono-tactical">PYTHON ACTIVE</span>
                        </div>
                        <p class="text-[9px] text-zinc-500 leading-normal">Mapea infraestructura resolviendo dominios o IPs de forma directa en el backend.</p>
                        <div class="flex gap-2">
                            <input type="text" id="osint-ip-input" placeholder="Ej: google.com o 8.8.8.8" class="flex-1 bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-zinc-200 text-xs focus:border-cyan-500/60 outline-none">
                            <button onclick="traceIP()" class="bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-semibold px-3 rounded text-xs transition">Rastrear</button>
                        </div>
                    </div>

                    <!-- EXIF metadata extractor -->
                    <div class="border border-zinc-800 bg-zinc-900/20 rounded-md p-3 space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-[10px] font-semibold text-cyan-400 uppercase"><i class="fa-solid fa-image mr-1"></i>Forense EXIF GPS</span>
                            <span class="text-[8px] bg-emerald-950/40 text-emerald-400 px-1.5 py-0.2 rounded font-semibold font-mono-tactical">PILLOW PARSER</span>
                        </div>
                        <p class="text-[9px] text-zinc-500 leading-normal">Sube una fotografía. El servidor procesará la cabecera binaria buscando coordenadas GPS.</p>
                        <label class="block border border-dashed border-zinc-800 rounded-md p-3 text-center bg-zinc-950 hover:border-cyan-500/50 cursor-pointer transition">
                            <i class="fa-solid fa-cloud-arrow-up text-cyan-500 text-sm mb-1 block"></i>
                            <span class="text-[10px] text-zinc-300 block font-medium">Subir Imagen Fotográfica</span>
                            <span class="text-[8px] text-zinc-600 block mt-0.5 font-mono-tactical">Procesamiento backend de .jpg / .jpeg</span>
                            <input type="file" id="exif-image-file" class="hidden" accept=".jpg,.jpeg" onchange="processExifImage(event)">
                        </label>
                    </div>

                    <!-- Google Dorks generator -->
                    <div class="border border-zinc-800 bg-zinc-900/20 rounded-md p-3 space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-[10px] font-semibold text-cyan-400 uppercase"><i class="fa-solid fa-magnifying-glass-plus mr-1"></i>Google Dorks</span>
                            <span class="text-[8px] bg-zinc-800 text-zinc-400 px-1.5 py-0.2 rounded font-semibold font-mono-tactical">RECON</span>
                        </div>
                        <div class="space-y-2">
                            <label class="text-[9px] text-zinc-500 block">Tipo de Vulnerabilidad:</label>
                            <select id="dork-type" onchange="updateDorkPreview()" class="w-full bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-xs text-zinc-300 outline-none">
                                <option value="cams">Cámaras Web Abiertas (CCTV)</option>
                                <option value="docs">Documentos Confidenciales Expuestos</option>
                                <option value="admin">Paneles de Administración Expuestos</option>
                                <option value="logins">Páginas de Login con Credenciales</option>
                            </select>
                            <div class="bg-zinc-950 p-2 rounded text-[10px] font-mono-tactical text-amber-500 select-all border border-zinc-900 break-words" id="dork-preview">
                                inurl:"viewerframe?mode=motion"
                            </div>
                            <button onclick="launchDork()" class="w-full bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-cyan-400 font-semibold py-1.5 px-2 rounded text-[10px] transition">
                                <i class="fa-solid fa-external-link mr-1"></i>Lanzar Búsqueda Externa
                            </button>
                        </div>
                    </div>

                    <!-- Alias Recon (Social sweep) -->
                    <div class="border border-zinc-800 bg-zinc-900/20 rounded-md p-3 space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-[10px] font-semibold text-cyan-400 block uppercase"><i class="fa-solid fa-address-book mr-1"></i>Recon de Alias</span>
                            <span class="text-[8px] bg-emerald-950/40 text-emerald-400 px-1.5 py-0.2 rounded font-semibold font-mono-tactical">LIVE PROBE</span>
                        </div>
                        <p class="text-[9px] text-zinc-500 leading-normal">Comprobación física de la presencia del usuario en servidores de redes.</p>
                        <div class="flex gap-2">
                            <input type="text" id="osint-username" placeholder="Alias a rastrear" class="flex-1 bg-zinc-900 border border-zinc-800 rounded px-2 py-1 text-zinc-200 text-xs focus:border-cyan-500/60 outline-none">
                            <button onclick="reconUsername()" class="bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-semibold px-3 rounded text-xs transition">Rastrear</button>
                        </div>
                        <div id="username-results" class="grid grid-cols-2 gap-2 pt-1 text-[9px] hidden font-mono-tactical">
                            <div id="recon-res-github" class="p-1 border border-zinc-800 rounded bg-zinc-900/40 text-zinc-300 block text-center">
                                <i class="fa-brands fa-github text-cyan-400 mr-1"></i>GitHub: <span class="status-indicator">--</span>
                            </div>
                            <div id="recon-res-twitter" class="p-1 border border-zinc-800 rounded bg-zinc-900/40 text-zinc-300 block text-center">
                                <i class="fa-brands fa-twitter text-cyan-400 mr-1"></i>X (Twitter): <span class="status-indicator">--</span>
                            </div>
                            <div id="recon-res-reddit" class="p-1 border border-zinc-800 rounded bg-zinc-900/40 text-zinc-300 block text-center">
                                <i class="fa-brands fa-reddit text-cyan-400 mr-1"></i>Reddit: <span class="status-indicator">--</span>
                            </div>
                            <div id="recon-res-tiktok" class="p-1 border border-zinc-800 rounded bg-zinc-900/40 text-zinc-300 block text-center">
                                <i class="fa-brands fa-tiktok text-cyan-400 mr-1"></i>TikTok: <span class="status-indicator">--</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- TAB 3: GEMMA AI -->
                <div id="tab-content-gemma" class="hidden space-y-4">
                    <div class="border border-zinc-800 bg-zinc-900/20 rounded-md p-3 space-y-2">
                        <span class="text-[10px] font-semibold text-cyan-400 block uppercase"><i class="fa-solid fa-draw-polygon mr-1"></i>Perímetro Táctico Regional</span>
                        <p class="text-[9px] text-zinc-500 leading-normal">Selecciona un área de un radio máximo de **500 Metros** en el mapa para estudiar de forma instantánea la psicología colectiva y la moral general del sector.</p>
                        
                        <button onclick="togglePerimeterDrawTool()" id="btn-perimeter-tool" class="w-full py-2 px-3 border border-dashed border-cyan-500/20 bg-cyan-950/5 hover:bg-cyan-950/15 text-cyan-400 font-semibold rounded-md flex items-center justify-center gap-2 transition text-[10px]">
                            <i class="fa-solid fa-crosshairs animate-pulse"></i> <span id="perimeter-btn-text">Activar Selección (Mapa)</span>
                        </button>
                    </div>

                    <div id="perimeter-results-hud" class="border border-zinc-800 bg-zinc-950/30 rounded-md p-3.5 space-y-3 relative overflow-hidden hidden">
                        <div class="absolute top-0 right-0 p-1 text-[8px] bg-cyan-950/30 text-cyan-400 font-semibold border-l border-b border-zinc-800 font-mono-tactical">500M COV</div>
                        
                        <div class="space-y-1">
                            <span class="text-[9px] text-zinc-600 uppercase block font-semibold">Coordenadas Seleccionadas</span>
                            <div class="text-[10px] font-bold text-zinc-300 font-mono-tactical" id="gemma-target-coords">LAT: 00.00000 | LNG: 00.00000</div>
                        </div>

                        <div class="grid grid-cols-2 gap-2 text-[10px]">
                            <div class="p-2 border border-zinc-800 rounded bg-zinc-900/20">
                                <span class="text-[8px] text-zinc-500 block uppercase">Población Estimada</span>
                                <span class="text-cyan-400 font-bold text-xs" id="gemma-pop-calc">0 habs</span>
                            </div>
                            <div class="p-2 border border-zinc-800 rounded bg-zinc-900/20">
                                <span class="text-[8px] text-zinc-500 block uppercase">Hogares Densidad</span>
                                <span class="text-cyan-400 font-bold text-xs" id="gemma-homes-calc">0 hogares</span>
                            </div>
                        </div>

                        <div class="space-y-1.5 border-t border-b border-zinc-800 py-3">
                            <div class="flex justify-between items-center text-[9px]">
                                <span class="text-zinc-400 uppercase font-semibold"><i class="fa-solid fa-heart-pulse text-rose-500 mr-1"></i>Moral Colectiva:</span>
                                <span class="font-bold text-emerald-400 font-mono-tactical" id="gemma-moral-text">ESTABLE (75%)</span>
                            </div>
                            <div class="w-full bg-zinc-900 rounded-full h-1 overflow-hidden">
                                <div id="gemma-moral-bar" class="bg-gradient-to-r from-red-500 via-amber-500 to-emerald-500 h-1 w-3/4 rounded-full transition-all duration-300"></div>
                            </div>
                        </div>

                        <div class="space-y-1.5">
                            <div class="flex justify-between items-center">
                                <span class="text-[9px] text-cyan-400 font-semibold tracking-wider uppercase block"><i class="fa-solid fa-comment-medical mr-1"></i>Diagnóstico Psicológico</span>
                                <button onclick="copyCurrentCoords()" class="text-zinc-500 hover:text-cyan-400 text-[9px] font-mono-tactical"><i class="fa-regular fa-copy mr-1"></i>Copiar</button>
                            </div>
                            <div class="bg-zinc-950 p-2.5 border border-zinc-800 rounded-md text-[9.5px] text-zinc-400 leading-relaxed max-h-36 overflow-y-auto" id="gemma-psychological-box">
                                Esperando selección en mapa...
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- COLLAPSE GRAB-TAB -->
            <button onclick="toggleLeftSidebar()" class="absolute top-1/2 -right-5 -translate-y-1/2 w-5 h-11 bg-zinc-950 border-t border-b border-r border-zinc-800 rounded-r flex items-center justify-center text-zinc-500 hover:text-cyan-400 hover:bg-zinc-900 cursor-pointer shadow-md z-50 transition-colors">
                <i class="fa-solid fa-chevron-left text-[10px]" id="left-sidebar-icon"></i>
            </button>
        </div>

        <!-- MAIN MAP SPACE -->
        <div class="flex-1 flex flex-col relative h-full bg-[#09090b]">
            
            <!-- Target Ingest search bar -->
            <div class="absolute top-3 left-1/2 -translate-x-1/2 z-[25] w-full max-w-[280px] xs:max-w-xs sm:max-w-md px-2">
                <div class="bg-zinc-950/95 border border-zinc-800 shadow-lg rounded-md p-1.5 flex gap-1.5 items-center">
                    <div class="pl-2">
                        <i class="fa-solid fa-satellite text-cyan-500 text-xs"></i>
                    </div>
                    <input type="text" id="map-search" placeholder="Buscar Territorio (País/Estado)..." class="flex-1 bg-transparent border-none text-[11px] outline-none text-zinc-200 placeholder-zinc-500 font-mono-tactical">
                    <button onclick="handleSearch()" class="bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-semibold text-[10px] px-3 py-1 rounded transition-colors flex items-center gap-1 shrink-0">
                        <i class="fa-solid fa-cloud-arrow-down"></i>Ingerir
                    </button>
                </div>
            </div>

            <!-- Layer selectors and 2D/3D switcher -->
            <div class="absolute bottom-4 left-4 z-[25] flex flex-col gap-2">
                <!-- Simplified Map Selector: Only Sat and Digital -->
                <div class="bg-zinc-950/95 border border-zinc-800 rounded-md p-1.5 shadow-md space-y-1 text-[9px] flex flex-col" id="map-layer-selector">
                    <span class="text-zinc-600 font-semibold px-1 uppercase tracking-wider font-mono-tactical">Vistas Digitales</span>
                    <button onclick="switchTileLayer('sat')" id="layer-btn-sat" class="px-2 py-1 text-left bg-cyan-950/30 text-cyan-400 rounded font-semibold transition-colors">Satelital Real HD</button>
                    <button onclick="switchTileLayer('digital')" id="layer-btn-digital" class="px-2 py-1 text-left hover:bg-zinc-900 rounded text-zinc-500 transition-colors">Tactical Digital (CRT)</button>
                </div>
                
                <div class="flex gap-2">
                    <button onclick="setViewMode(false)" id="btn-view-2d" class="flex-1 py-1 px-3 border border-cyan-500/40 bg-cyan-950/20 text-cyan-400 font-semibold rounded-md text-[10px] shadow-sm transition-colors">
                        <i class="fa-solid fa-map mr-1"></i>2D MAP
                    </button>
                    <button onclick="setViewMode(true)" id="btn-view-3d" class="flex-1 py-1 px-3 border border-zinc-800 bg-zinc-950 hover:border-cyan-500/40 text-zinc-500 hover:text-cyan-400 font-semibold rounded-md text-[10px] shadow-sm transition-colors">
                        <i class="fa-solid fa-earth-americas mr-1"></i>3D GLOBE
                    </button>
                </div>
            </div>

            <!-- 2D MAP CANVAS (Leaflet) -->
            <div id="map" class="flex-1 w-full h-full z-10 transition-opacity duration-300 no-filter"></div>

            <!-- 3D GLOBE CANVAS (Three.js) -->
            <div id="container-3d" class="absolute inset-0 w-full h-full z-0 bg-[#09090b] hidden overflow-hidden">
                <div id="canvas-3d-wrapper" class="w-full h-full"></div>
                <div class="absolute top-16 right-4 p-2 border border-zinc-800 bg-zinc-950/90 rounded text-[8.5px] text-cyan-400 font-mono-tactical space-y-1 pointer-events-none">
                    <span class="text-zinc-600 font-semibold block uppercase">Estado de Órbita</span>
                    <div>CÁM_X: <span id="cam-x">0.0</span></div>
                    <div>CÁM_Y: <span id="cam-y">0.0</span></div>
                    <div class="text-[7.5px] text-zinc-500 italic mt-0.5">Arrastre para rotar el planeta.</div>
                </div>
            </div>

            <!-- Loading Intercepting Overlay Screen -->
            <div id="osint-loader" class="absolute inset-0 bg-zinc-950/85 backdrop-blur-xs z-[100] flex flex-col items-center justify-center p-4 text-center hidden">
                <div class="relative w-20 h-20 mb-3 flex items-center justify-center">
                    <div class="absolute inset-0 border border-cyan-500/20 rounded-full"></div>
                    <div class="absolute inset-2 border-2 border-dashed border-cyan-400/40 rounded-full animate-spin-slow" style="animation-duration: 8s;"></div>
                    <div class="absolute inset-0 border-t-2 border-cyan-500 rounded-full animate-spin"></div>
                    <i class="fa-solid fa-crosshairs text-cyan-400 text-xl absolute"></i>
                </div>
                <h3 class="text-xs font-semibold text-cyan-400 tracking-wider mb-1">PROCESANDO CONSULTA SATELLITE</h3>
                <p id="osint-loader-status" class="text-[9.5px] text-zinc-500 max-w-sm font-mono-tactical h-8">Interceptando flujos de datos...</p>
                <div class="w-40 bg-zinc-900 rounded-full h-0.5 mt-2 overflow-hidden border border-zinc-800">
                    <div class="bg-cyan-500 h-0.5 rounded-full animate-infinite-loading w-1/2"></div>
                </div>
            </div>

        </div>

        <!-- RIGHT SIDEBAR -->
        <div id="right-sidebar" class="panel-transition w-80 border-l border-zinc-800 bg-[#09090b]/98 flex flex-col h-full shrink-0 z-30 relative shadow-xl">
            
            <div class="flex-1 overflow-y-auto p-3.5 space-y-4 text-xs">
                
                <!-- CCTV CCTV SYSTEM SIMULATION -->
                <div class="border border-zinc-800 bg-zinc-900/20 rounded-md p-3 space-y-2">
                    <span class="text-[10px] font-semibold text-cyan-400 block uppercase font-mono-tactical"><i class="fa-solid fa-video mr-1 text-red-500"></i>CCTV Termal Vectorial</span>
                    
                    <div class="aspect-video relative bg-[#09090b] rounded border border-zinc-800 overflow-hidden">
                        <canvas id="cctv-canvas" class="w-full h-full block"></canvas>
                        <div class="absolute top-2 left-2 text-[7.5px] bg-red-950/40 px-1 py-0.2 text-red-400 font-mono-tactical font-semibold rounded">REC</div>
                        <div class="absolute top-2 right-2 text-[7.5px] text-zinc-500 font-mono-tactical" id="cctv-time">00:00:00</div>
                        <div class="absolute bottom-2 left-2 text-[7.5px] text-cyan-400 font-mono-tactical">SECTOR: GLOB_SAT_05</div>
                        <div class="absolute bottom-2 right-2 text-[7.5px] text-zinc-500 font-mono-tactical" id="cctv-fps">8 FPS</div>
                    </div>

                    <div class="flex gap-1.5">
                        <button onclick="setCameraMode('thermal')" id="btn-cam-thermal" class="flex-1 py-1 bg-cyan-950/20 text-cyan-400 border border-cyan-500/20 text-[9px] font-semibold rounded">TERMAL</button>
                        <button onclick="setCameraMode('radar')" id="btn-cam-radar" class="flex-1 py-1 hover:bg-zinc-800 text-zinc-500 text-[9px] font-semibold rounded transition-colors">BARRIDO RADAR</button>
                    </div>
                </div>

                <!-- REAL INCIDENTS FEED LIST -->
                <div class="space-y-2 flex-1 flex flex-col">
                    <div class="flex items-center justify-between border-b border-zinc-800 pb-1.5 shrink-0">
                        <span class="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider"><i class="fa-solid fa-rss mr-1"></i>Últimos Sucesos</span>
                        <span class="text-[8px] text-zinc-500 font-mono-tactical" id="events-count">0 Eventos</span>
                    </div>

                    <div id="event-feed-list" class="space-y-2.5 flex-1 overflow-y-auto max-h-[calc(100vh-320px)] pr-1">
                        <div class="p-3 border border-zinc-800 rounded-md bg-zinc-950 text-center text-zinc-600 italic text-[10px]">
                            Cargando datos satelitales en tiempo real...
                        </div>
                    </div>
                </div>

            </div>

            <!-- COLLAPSE GRAB-TAB -->
            <button onclick="toggleRightSidebar()" class="absolute top-1/2 -left-5 -translate-y-1/2 w-5 h-11 bg-zinc-950 border-t border-b border-l border-zinc-800 rounded-l flex items-center justify-center text-zinc-500 hover:text-cyan-400 hover:bg-zinc-900 cursor-pointer shadow-md z-50 transition-colors">
                <i class="fa-solid fa-chevron-right text-[10px]" id="right-sidebar-icon"></i>
            </button>
        </div>

    </div>

    <script>
        let map;
        let activeTileLayer;
        let currentMapStyle = 'sat'; 
        let leftSidebarOpen = true;
        let rightSidebarOpen = true;
        let currentLeftTab = 'console';
        
        let perimeterToolActive = false;
        let activePerimeterCircle = null;
        let audioCtx = null; 
        let logsTerminal = null;

        let userBaseCoordinates = null;
        let userBaseMarker = null;
        let tacticalGeodesicLine = null;

        let incidentEvents = [];

        // 3D parameters
        let scene3D, camera3D, renderer3D, globe3D, pointSpikesGroup;
        let is3DModeActive = false;
        let orbitAngles = { theta: 0, phi: Math.PI / 2 };
        let isDraggingGlobe = false;
        let previousMousePosition = { x: 0, y: 0 };
        let telemetryChartInstance = null;
        let telemetryDataPoints = Array(20).fill(15);

        // CCTV rendering variables
        let cctvCanvas, cctvCtx;
        let cctvMode = 'thermal';
        let cctvFrame = 0;

        function initAudioContext() {
            if (!audioCtx) {
                audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            }
        }

        function playTacticalSound(type) {
            try {
                initAudioContext();
                if (!audioCtx || audioCtx.state === 'suspended') return;

                const osc = audioCtx.createOscillator();
                const gain = audioCtx.createGain();
                osc.connect(gain);
                gain.connect(audioCtx.destination);

                const now = audioCtx.currentTime;

                if (type === 'click') {
                    osc.type = 'sine';
                    osc.frequency.setValueAtTime(1000, now);
                    gain.gain.setValueAtTime(0.015, now);
                    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.08);
                    osc.start(now);
                    osc.stop(now + 0.08);
                } else if (type === 'ping') {
                    osc.type = 'sine';
                    osc.frequency.setValueAtTime(800, now);
                    gain.gain.setValueAtTime(0.02, now);
                    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.4);
                    osc.start(now);
                    osc.stop(now + 0.4);
                } else if (type === 'alarm') {
                    osc.type = 'sawtooth';
                    osc.frequency.setValueAtTime(160, now);
                    osc.frequency.linearRampToValueAtTime(260, now + 0.2);
                    osc.frequency.linearRampToValueAtTime(160, now + 0.4);
                    gain.gain.setValueAtTime(0.015, now);
                    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.4);
                    osc.start(now);
                    osc.stop(now + 0.4);
                } else if (type === 'success') {
                    osc.type = 'triangle';
                    osc.frequency.setValueAtTime(523, now);
                    osc.frequency.setValueAtTime(659, now + 0.1);
                    osc.frequency.setValueAtTime(784, now + 0.2);
                    gain.gain.setValueAtTime(0.02, now);
                    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.5);
                    osc.start(now);
                    osc.stop(now + 0.5);
                }
            } catch (e) {
                console.warn('Audio Context error:', e);
            }
        }

        function writeLog(text, level = 'info') {
            if (!logsTerminal) return;
            const now = new Date();
            const timeStr = `${String(now.getUTCHours()).padStart(2, '0')}:${String(now.getUTCMinutes()).padStart(2, '0')}:${String(now.getUTCSeconds()).padStart(2, '0')}`;
            
            let color = 'text-zinc-400';
            if (level === 'warning') color = 'text-amber-500';
            if (level === 'critical') color = 'text-rose-500';
            if (level === 'success') color = 'text-cyan-400';

            const logRow = document.createElement('div');
            logRow.className = `${color} leading-snug`;
            logRow.innerText = `[${timeStr}] ${text}`;
            
            logsTerminal.appendChild(logRow);
            logsTerminal.scrollTop = logsTerminal.scrollHeight;
        }

        window.onload = async function() {
            logsTerminal = document.getElementById('log-terminal');
            
            setInterval(updateClock, 1000);
            initTelemetryChart();
            setInterval(updateTelemetryData, 4000);

            if (window.innerWidth < 1024) {
                leftSidebarOpen = false;
                rightSidebarOpen = false;
                applySidebarStates();
            } else {
                applySidebarStates();
            }

            initMap2D();
            init3DGlobe();
            initCCTV();

            updateDorkPreview();

            document.body.addEventListener('click', () => {
                initAudioContext();
            }, { once: true });

            await geolocalizeUserOnStart();
            await fetchLiveRealData();

            // Set default dynamic console view matching initial layer "sat"
            updateDynamicConsolePanel();

            writeLog('Sistema SentryGlobe Cargado y Sincronizado con Python Server.', 'success');
        };

        function updateClock() {
            const now = new Date();
            const timeStr = now.toUTCString().split(' ')[4] + ' UTC';
            document.getElementById('utc-clock').innerText = timeStr;
            document.getElementById('cctv-time').innerText = now.toUTCString().split(' ')[4];
            
            const crtTime = document.getElementById('crt-terminal-time');
            if (crtTime) {
                const year = now.getUTCFullYear();
                const month = String(now.getUTCMonth() + 1).padStart(2, '0');
                const day = String(now.getUTCDate()).padStart(2, '0');
                crtTime.innerText = `${year}-${month}-${day} ${now.toUTCString().split(' ')[4]}`;
            }
        }

        async function geolocalizeUserOnStart() {
            writeLog('Detectando firma geográfica de red...', 'info');
            try {
                // Fetch local user metadata using Python proxy or standard secure SSL tracker
                const res = await fetch('https://ipapi.co/json/');
                const data = await res.json();
                if (data && data.latitude && data.longitude) {
                    userBaseCoordinates = { lat: data.latitude, lng: data.longitude };
                    writeLog(`Estación Central Localizada: ${data.city}, ${data.country_name} (${data.ip})`, 'success');
                    
                    drawBaseStationMarker();
                    map.setView([data.latitude, data.longitude], 4);
                } else {
                    writeLog('Geolocalización por IP rechazada o inaccesible.', 'warning');
                }
            } catch (e) {
                writeLog('Error de red al geolocalizar estación local.', 'warning');
            }
        }

        function drawBaseStationMarker() {
            if (!map || !userBaseCoordinates) return;
            if (userBaseMarker) {
                map.removeLayer(userBaseMarker);
            }

            const customBaseIcon = L.divIcon({
                html: `
                    <div class="relative w-6 h-6 flex items-center justify-center">
                        <span class="absolute w-4 h-4 rounded-lg bg-emerald-500/20 border border-emerald-400 animate-ping"></span>
                        <i class="fa-solid fa-house-laptop text-emerald-400 text-[10px] absolute z-20"></i>
                    </div>
                `,
                className: 'base-station-marker',
                iconSize: [24, 24],
                iconAnchor: [12, 12]
            });

            userBaseMarker = L.marker([userBaseCoordinates.lat, userBaseCoordinates.lng], { icon: customBaseIcon })
                .addTo(map)
                .bindPopup(`<div class="bg-zinc-950 text-emerald-400 p-2 font-mono-tactical text-[9px] border border-zinc-800">ESTACIÓN CENTRAL OPERATIVA</div>`);
        }

        async function fetchLiveRealData() {
            writeLog('Iniciando ingesta de Datos Geológicos Reales (USGS)...', 'info');
            
            try {
                const usgsRes = await fetch('https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson');
                const usgsData = await usgsRes.json();
                
                if (usgsData.features) {
                    writeLog(`Ingeridos exitosamente ${usgsData.features.length} sismos globales del USGS.`, 'success');
                    usgsData.features.slice(0, 30).forEach(f => {
                        const [lng, lat] = f.geometry.coordinates;
                        incidentEvents.push({
                            id: f.id,
                            title: `Sismo M ${f.properties.mag} - ${f.properties.place}`,
                            category: 'Geológico',
                            severity: f.properties.mag >= 5.0 ? 'CRITICAL' : 'WARNING',
                            locationName: f.properties.place,
                            lat: lat,
                            lng: lng,
                            time: new Date(f.properties.time).toUTCString().split(' ')[4] + ' UTC',
                            desc: `${f.properties.title}. Profundidad: ${f.geometry.coordinates[2]} km. Reporte geológico de sismógrafos globales.`,
                            sensorCode: `USGS-${f.id.toUpperCase()}`,
                            sources: [{ uri: f.properties.url, title: 'USGS Earthquake' }]
                        });
                    });
                }
            } catch (e) {
                writeLog('Fallo al conectar con la API de Sismología del USGS.', 'warning');
            }

            writeLog('Iniciando ingesta de Eventos Climáticos de la NASA (EONET)...', 'info');
            try {
                const nasaRes = await fetch('https://eonet.gsfc.nasa.gov/api/v3/events?limit=20&status=open');
                const nasaData = await nasaRes.json();
                
                if (nasaData.events) {
                    writeLog(`Ingeridos exitosamente ${nasaData.events.length} eventos ambientales satelitales de la NASA.`, 'success');
                    nasaData.events.forEach(e => {
                        let geom = e.geometry && e.geometry[0];
                        if (geom && geom.coordinates && geom.type === 'Point') {
                            const [lng, lat] = geom.coordinates;
                            const cat = e.categories && e.categories[0] ? e.categories[0].title : 'Ambiental';
                            
                            let translatedCat = 'Climático';
                            if (cat === 'Volcanoes') translatedCat = 'Volcánico';
                            if (cat === 'Wildfires') translatedCat = 'Incendio Forestal';
                            if (cat === 'Severe Storms') translatedCat = 'Tormenta Severa';
                            if (cat === 'Sea and Lake Ice') translatedCat = 'Capa de Hielo';

                            incidentEvents.push({
                                id: e.id,
                                title: e.title,
                                category: translatedCat,
                                severity: 'WARNING',
                                locationName: 'Localización Satelital NASA',
                                lat: lat,
                                lng: lng,
                                time: new Date(geom.date).toUTCString().split(' ')[4] + ' UTC',
                                desc: `Actividad extrema reportada y confirmada visualmente por los satélites meteorológicos de la NASA (EONET Catalog ID: ${e.id}).`,
                                sensorCode: `NASA-${e.id}`,
                                sources: e.sources && e.sources[0] ? [{ uri: e.sources[0].url, title: e.sources[0].id }] : [{ uri: 'https://eonet.gsfc.nasa.gov/', title: 'NASA EONET' }]
                            });
                        }
                    });
                }
            } catch (e) {
                writeLog('Fallo al conectar con la API de Eventos Satelitales EONET de la NASA.', 'warning');
            }

            refreshMapMarkers();
            playTacticalSound('success');
        }

        function toggleLeftSidebar() {
            playTacticalSound('click');
            leftSidebarOpen = !leftSidebarOpen;
            applySidebarStates();
        }

        function toggleRightSidebar() {
            playTacticalSound('click');
            rightSidebarOpen = !rightSidebarOpen;
            applySidebarStates();
        }

        function applySidebarStates() {
            const leftSidebar = document.getElementById('left-sidebar');
            const rightSidebar = document.getElementById('right-sidebar');
            const leftIcon = document.getElementById('left-sidebar-icon');
            const rightIcon = document.getElementById('right-sidebar-icon');

            if (leftSidebarOpen) {
                leftSidebar.style.transform = 'translate3d(0, 0, 0)';
                leftIcon.className = 'fa-solid fa-chevron-left text-[10px]';
            } else {
                leftSidebar.style.transform = 'translate3d(-100%, 0, 0)';
                leftIcon.className = 'fa-solid fa-chevron-right text-[10px]';
            }

            if (rightSidebarOpen) {
                rightSidebar.style.transform = 'translate3d(0, 0, 0)';
                rightIcon.className = 'fa-solid fa-chevron-right text-[10px]';
            } else {
                rightSidebar.style.transform = 'translate3d(100%, 0, 0)';
                rightIcon.className = 'fa-solid fa-chevron-left text-[10px]';
            }

            setTimeout(() => {
                if (map) {
                    map.invalidateSize({ animate: true });
                }
            }, 300);
        }

        function switchLeftTab(tabName) {
            playTacticalSound('click');
            currentLeftTab = tabName;

            const tabs = ['console', 'osint', 'gemma'];
            tabs.forEach(t => {
                const btn = document.getElementById(`btn-tab-${t}`);
                const content = document.getElementById(`tab-content-${t}`);
                if (t === tabName) {
                    btn.classList.add('border-cyan-500', 'text-cyan-400');
                    btn.classList.remove('border-transparent', 'text-zinc-500');
                    content.classList.remove('hidden');
                } else {
                    btn.classList.remove('border-cyan-500', 'text-cyan-400');
                    btn.classList.add('border-transparent', 'text-zinc-500');
                    content.classList.add('hidden');
                }
            });
        }

        function toggleKeyVisibility() {
            const keyInput = document.getElementById('gemma-key');
            const eyeIcon = document.getElementById('key-eye');
            if (keyInput.type === 'password') {
                keyInput.type = 'text';
                eyeIcon.className = 'fa-regular fa-eye-slash text-[9px]';
            } else {
                keyInput.type = 'password';
                eyeIcon.className = 'fa-regular fa-eye text-[9px]';
            }
        }

        function initMap2D() {
            map = L.map('map', {
                center: [20.0, 0.0],
                zoom: 2,
                zoomControl: false,
                attributionControl: false
            });

            // Default Map Layer: HD SAT
            activeTileLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
                maxZoom: 19
            }).addTo(map);

            map.on('click', function(e) {
                if (perimeterToolActive) {
                    executePerimeterAnalysis(e.latlng.lat, e.latlng.lng);
                }
            });

            refreshMapMarkers();
        }

        // Simplified map layer selection: ONLY "sat" or "digital"
        function switchTileLayer(layerType) {
            playTacticalSound('click');
            if (activeTileLayer) {
                map.removeLayer(activeTileLayer);
            }

            let url = '';
            const btnSat = document.getElementById('layer-btn-sat');
            const btnDigital = document.getElementById('layer-btn-digital');
            const mapContainer = document.getElementById('map');

            [btnSat, btnDigital].forEach(b => {
                b.className = "px-2 py-1 text-left hover:bg-zinc-900 rounded text-zinc-500 transition-colors";
            });

            currentMapStyle = layerType;

            if (layerType === 'sat') {
                url = 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}';
                btnSat.className = "px-2 py-1 text-left bg-cyan-950/30 text-cyan-400 rounded font-semibold transition-colors";
                mapContainer.className = "flex-1 w-full h-full z-10 transition-opacity duration-300 no-filter";
                writeLog('Capa de mapa cambiada a Satelital HD Real (Esri)', 'info');
            } else if (layerType === 'digital') {
                // CartoDB Dark Matter
                url = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
                btnDigital.className = "px-2 py-1 text-left bg-cyan-950/30 text-cyan-400 rounded font-semibold transition-colors";
                mapContainer.className = "flex-1 w-full h-full z-10 transition-opacity duration-300 crt-green-filter";
                writeLog('Capa de mapa cambiada a Vectorial Digital (Filtro CRT)', 'warning');
            }

            activeTileLayer = L.tileLayer(url, {
                maxZoom: 19
            }).addTo(map);

            updateDynamicConsolePanel();
        }

        function updateDynamicConsolePanel() {
            const container = document.getElementById('dynamic-console-section');
            if (!container) return;

            if (currentMapStyle === 'sat') {
                // SATELLITE SUPPLIERS PANEL
                container.innerHTML = `
                    <div class="border border-zinc-800 bg-zinc-900/20 rounded-md p-3 space-y-2.5">
                        <div class="flex items-center justify-between border-b border-zinc-800 pb-1.5">
                            <span class="text-[9px] text-cyan-400 font-bold uppercase tracking-wider"><i class="fa-solid fa-circle-info mr-1.5"></i>PROVEEDORES SATELEST (HD)</span>
                            <span class="text-[8px] bg-cyan-950 text-cyan-400 px-1.5 py-0.2 rounded font-semibold font-mono-tactical font-bold">ACTIVO</span>
                        </div>
                        <p class="text-[9.5px] text-zinc-400 leading-normal">
                            La vista activa unifica múltiples constelaciones satelitales en tiempo real para optimizar la resolución en zoom alto:
                        </p>
                        <div class="space-y-2 font-mono-tactical text-[9.5px]">
                            <div class="p-1.5 bg-zinc-950/60 rounded border border-zinc-800/60">
                                <span class="text-cyan-400 font-bold">1. Esri World Imagery</span>
                                <div class="text-[8.5px] text-zinc-500 mt-0.5">Soporte principal de texturas ortorrectificadas a escala global. Revestimiento de parches multirresolución.</div>
                            </div>
                            <div class="p-1.5 bg-zinc-950/60 rounded border border-zinc-800/60">
                                <span class="text-cyan-400 font-bold">2. Maxar Technologies</span>
                                <div class="text-[8.5px] text-zinc-500 mt-0.5">Constelación WorldView-3 & 4. Provee imágenes comerciales de resolución submétrica de hasta 30cm por pixel.</div>
                            </div>
                            <div class="p-1.5 bg-zinc-950/60 rounded border border-zinc-800/60">
                                <span class="text-cyan-400 font-bold">3. Airbus DS (SPOT & Pléiades)</span>
                                <div class="text-[8.5px] text-zinc-500 mt-0.5">Firma de defensa y espacio aérea que proporciona revisitas diarias continuas para control táctico regional.</div>
                            </div>
                            <div class="p-1.5 bg-zinc-950/60 rounded border border-zinc-800/60">
                                <span class="text-cyan-400 font-bold">4. USGS / NASA (Landsat)</span>
                                <div class="text-[8.5px] text-zinc-500 mt-0.5">Imágenes multiespectrales con análisis espectral térmico para estudio de suelo y detección de calor.</div>
                            </div>
                            <div class="p-1.5 bg-zinc-950/60 rounded border border-zinc-800/60">
                                <span class="text-cyan-400 font-bold">5. Copernicus Sentinel (ESA)</span>
                                <div class="text-[8.5px] text-zinc-500 mt-0.5">Vigilancia continental pública radar y óptica con barrido radar activo sobre nubes y tormentas.</div>
                            </div>
                        </div>
                    </div>
                `;
            } else {
                // DIGITAL CRT VIEW INSPIRED IN image_9271a8.jpg
                container.innerHTML = `
                    <div class="crt-terminal p-3 rounded-md font-mono-tactical relative text-[9px] crt-glow space-y-2">
                        <div class="flex items-center justify-between border-b border-green-800/50 pb-1">
                            <span class="font-bold tracking-wider text-[10px]">SENTRYGLOBE TERMINAL</span>
                            <span class="text-[7.5px] px-1 bg-[#004000] text-[#00ff00] rounded">CRT MODE</span>
                        </div>
                        
                        <!-- VECTORIAL GLOBAL MAP REPLICA -->
                        <div class="w-full h-24 bg-black/40 border border-green-950 relative rounded overflow-hidden">
                            <svg class="w-full h-full" viewBox="0 0 200 100" xmlns="http://www.w3.org/2000/svg">
                                <line x1="0" y1="20" x2="200" y2="20" class="crt-grid-line" />
                                <line x1="0" y1="40" x2="200" y2="40" class="crt-grid-line" />
                                <line x1="0" y1="60" x2="200" y2="60" class="crt-grid-line" />
                                <line x1="0" y1="80" x2="200" y2="80" class="crt-grid-line" />
                                
                                <line x1="40" y1="0" x2="40" y2="100" class="crt-grid-line" />
                                <line x1="80" y1="0" x2="80" y2="100" class="crt-grid-line" />
                                <line x1="120" y1="0" x2="120" y2="100" class="crt-grid-line" />
                                <line x1="160" y1="0" x2="160" y2="100" class="crt-grid-line" />

                                <!-- Simplified coastline path -->
                                <!-- North America -->
                                <path d="M 15,15 Q 25,12 35,22 T 40,30 T 35,45 T 25,40 Z" class="crt-coastline" />
                                <!-- South America -->
                                <path d="M 35,45 Q 45,55 42,70 T 38,90 T 32,80 T 30,55 Z" class="crt-coastline" />
                                <!-- Eurasia & Africa -->
                                <path d="M 75,15 Q 110,8 140,15 T 165,30 T 150,45 T 120,50 T 105,42 Z" class="crt-coastline" />
                                <path d="M 85,42 Q 105,45 100,60 T 95,85 T 80,65 T 82,50 Z" class="crt-coastline" />
                                <!-- Australia -->
                                <path d="M 145,65 Q 165,68 160,80 T 140,75 Z" class="crt-coastline" />
                                <path d="M 15,85 Q 25,87 40,88 T 120,89 T 170,88 Z" class="crt-coastline" />
                            </svg>
                            <div class="absolute bottom-1 right-1 text-[7px] text-[#00ff00] bg-black/60 px-0.5">SCALE: 1:25M</div>
                        </div>

                        <!-- REPLICA STATS & PROCEDURAL RUN LOGS -->
                        <div class="space-y-1 text-[#00ff00] text-[8.5px]">
                            <div>COORDS: <span class="font-bold">E/W LAT-GRID MASTER</span></div>
                            <div class="text-[7.5px] text-green-600">-------------------------------------------</div>
                            <div>&gt; NAVLOG.SYS LOADED <span class="text-[7px] text-green-600">[OK]</span></div>
                            <div>&gt; ACQUIRING GPS DATA... <span class="text-[7px] text-green-600">[CONNECT]</span></div>
                            <div>&gt; LAT/LON GRID: ACTIVE</div>
                            <div>&gt; SECTORS COMPILING: ACTIVE</div>
                            <div class="text-amber-500 font-bold">&gt; WARNING: MAGNETIC NORTH DEVIATION DETECTED</div>
                            <div>&gt; INPUT COMMAND: <span class="crt-cursor"></span></div>
                        </div>
                        <div class="border-t border-green-900/45 pt-1 mt-1 text-[8px] text-green-600 flex justify-between items-center">
                            <span>SENTRY_NODE_9271A8</span>
                            <span id="crt-terminal-time">00:00:00 UTC</span>
                        </div>
                    </div>
                `;
            }
        }

        let leafletMarkersGroup = L.layerGroup();
        
        function refreshMapMarkers() {
            leafletMarkersGroup.clearLayers();

            incidentEvents.forEach(evt => {
                let markerColor = '#06b6d4';
                if (evt.severity === 'WARNING') markerColor = '#f59e0b';
                if (evt.severity === 'CRITICAL') markerColor = '#ef4444';

                const customIcon = L.divIcon({
                    html: `
                        <div class="relative w-4 h-4 flex items-center justify-center">
                            <span class="absolute w-2 h-2 rounded-full" style="background-color: ${markerColor}; box-shadow: 0 0 6px ${markerColor}"></span>
                            <span class="radar-ping-node absolute w-full h-full" style="--ping-color: ${markerColor}"></span>
                        </div>
                    `,
                    className: 'custom-radar-marker',
                    iconSize: [16, 16],
                    iconAnchor: [8, 8]
                });

                const marker = L.marker([evt.lat, evt.lng], { icon: customIcon }).addTo(leafletMarkersGroup);
                
                const popupContent = `
                    <div class="bg-zinc-950 text-zinc-100 p-3 rounded border border-zinc-800 text-[10px] font-mono-tactical leading-relaxed" style="max-width: 220px">
                        <div class="flex items-center justify-between border-b border-zinc-800 pb-1 mb-1.5">
                            <span class="font-semibold text-cyan-400 uppercase tracking-wider">${evt.category}</span>
                            <span class="text-[8px] bg-zinc-900 px-1 rounded text-zinc-500">${evt.time}</span>
                        </div>
                        <h4 class="font-bold text-zinc-200 text-xs mb-1">${evt.title}</h4>
                        <p class="text-zinc-400 text-[9.5px] leading-normal">${evt.desc}</p>
                        <div class="mt-2 pt-1.5 border-t border-zinc-900 text-[8px] text-zinc-600 flex justify-between items-center">
                            <span>REG_ID: ${evt.sensorCode}</span>
                            <span>COORD: ${evt.lat.toFixed(3)}, ${evt.lng.toFixed(3)}</span>
                        </div>
                    </div>
                `;

                marker.bindPopup(popupContent, {
                    closeButton: false,
                    className: 'tactical-leaflet-popup'
                });

                marker.on('click', () => {
                    playTacticalSound('click');
                    drawGeodesicLink(evt.lat, evt.lng);
                });
            });

            leafletMarkersGroup.addTo(map);
            if (userBaseMarker) {
                userBaseMarker.addTo(map);
            }
            renderEventFeedList();
        }

        function renderEventFeedList() {
            const feedBox = document.getElementById('event-feed-list');
            document.getElementById('events-count').innerText = `${incidentEvents.length} Hechos`;

            if (incidentEvents.length === 0) {
                feedBox.innerHTML = `
                    <div class="p-3 border border-zinc-800 rounded bg-zinc-950 text-center text-zinc-600 italic text-[10px]">
                        Cargando telemetría satelital en tiempo real...
                    </div>
                `;
                return;
            }

            feedBox.innerHTML = '';
            incidentEvents.forEach(evt => {
                let borderTheme = 'border-zinc-850';
                let textTheme = 'text-cyan-400';
                let bgTheme = 'bg-zinc-900/10';

                if (evt.severity === 'WARNING') {
                    borderTheme = 'border-amber-900/30';
                    textTheme = 'text-amber-500';
                    bgTheme = 'bg-amber-950/2';
                } else if (evt.severity === 'CRITICAL') {
                    borderTheme = 'border-rose-900/40';
                    textTheme = 'text-rose-500 font-semibold';
                    bgTheme = 'bg-rose-950/2';
                }

                const card = document.createElement('div');
                card.className = `p-3 border rounded-md ${borderTheme} ${bgTheme} space-y-2 transition-colors hover:bg-zinc-900/35 relative overflow-hidden`;
                
                let sourcesHtml = '';
                if (evt.sources && evt.sources.length > 0) {
                    sourcesHtml = evt.sources.map(s => `
                        <a href="${s.uri}" target="_blank" class="inline-flex items-center gap-0.5 text-[8.5px] bg-zinc-950 border border-zinc-800 px-1 py-0.5 rounded text-cyan-400 hover:bg-zinc-900 transition-colors">
                            <i class="fa-solid fa-square-rss"></i> ${s.title}
                        </a>
                    `).join('');
                }

                card.innerHTML = `
                    <div class="flex items-center justify-between">
                        <span class="text-[8px] uppercase tracking-wider px-1.5 py-0.2 bg-zinc-900 text-zinc-400 rounded-sm font-semibold">${evt.category}</span>
                        <span class="text-[8.5px] text-zinc-500 font-mono-tactical">${evt.time}</span>
                    </div>
                    <h4 class="font-bold text-[10.5px] leading-snug cursor-pointer hover:text-cyan-400 transition-colors" onclick="panToIncident(${evt.lat}, ${evt.lng}, '${evt.id}')">
                        ${evt.title}
                    </h4>
                    <p class="text-[9.5px] text-zinc-500 leading-normal">${evt.desc}</p>
                    <div class="flex flex-wrap items-center justify-between gap-1 border-t border-zinc-900/60 pt-2 mt-1 text-[8.5px]">
                        <span class="text-zinc-600 font-mono-tactical">ID: ${evt.sensorCode}</span>
                        <div class="flex gap-1">
                            ${sourcesHtml}
                        </div>
                    </div>
                `;

                feedBox.appendChild(card);
            });
        }

        function panToIncident(lat, lng, id) {
            playTacticalSound('click');
            drawGeodesicLink(lat, lng);
            if (is3DModeActive) {
                rotate3DGlobeTo(lat, lng);
            } else {
                map.setView([lat, lng], 8, { animate: true });
            }
            writeLog(`Redireccionando sensor a: ${lat.toFixed(3)}, ${lng.toFixed(3)}`, 'success');
        }

        function drawGeodesicLink(targetLat, targetLng) {
            if (!userBaseCoordinates) return;
            
            if (tacticalGeodesicLine) {
                map.removeLayer(tacticalGeodesicLine);
            }

            tacticalGeodesicLine = L.polyline([
                [userBaseCoordinates.lat, userBaseCoordinates.lng],
                [targetLat, targetLng]
            ], {
                color: '#27272a',
                weight: 1,
                dashArray: '3, 3'
            }).addTo(map);

            const distance = calculateGeodeticDistance(userBaseCoordinates.lat, userBaseCoordinates.lng, targetLat, targetLng);
            writeLog(`Enlace de comunicación cifrado. Distancia: ${distance.toFixed(1)} km`, 'info');
        }

        function calculateGeodeticDistance(lat1, lon1, lat2, lon2) {
            const R = 6371; 
            const dLat = (lat2 - lat1) * Math.PI / 180;
            const dLon = (lon2 - lon1) * Math.PI / 180;
            const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
                      Math.sin(dLon / 2) * Math.sin(dLon / 2);
            const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
            return R * c;
        }

        function isWebGLSupported() {
            try {
                const canvas = document.createElement('canvas');
                return !!(window.WebGLRenderingContext && (canvas.getContext('webgl') || canvas.getContext('experimental-webgl')));
            } catch (e) {
                return false;
            }
        }

        function init3DGlobe() {
            if (!isWebGLSupported()) {
                disable3DInterface();
                return;
            }

            try {
                const container = document.getElementById('canvas-3d-wrapper');
                const width = container.clientWidth || 400;
                const height = container.clientHeight || 400;

                scene3D = new THREE.Scene();
                camera3D = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
                camera3D.position.z = 210;

                renderer3D = new THREE.WebGLRenderer({ antialias: true, alpha: true });
                renderer3D.setSize(width, height);
                renderer3D.setPixelRatio(Math.min(window.devicePixelRatio, 2)); 
                container.appendChild(renderer3D.domElement);

                const globeGeometry = new THREE.SphereGeometry(60, 32, 32); 
                
                // Procedural grid canvas textures to keep payload ultra light
                const canvasGrid = document.createElement('canvas');
                canvasGrid.width = 256;
                canvasGrid.height = 128;
                const ctxGrid = canvasGrid.getContext('2d');
                ctxGrid.fillStyle = '#09090b';
                ctxGrid.fillRect(0,0,256,128);
                ctxGrid.strokeStyle = '#27272a';
                ctxGrid.lineWidth = 1;
                
                for(let i=0; i<256; i+=16) {
                    ctxGrid.beginPath();
                    ctxGrid.moveTo(i, 0);
                    ctxGrid.lineTo(i, 128);
                    ctxGrid.stroke();
                }
                for(let j=0; j<128; j+=16) {
                    ctxGrid.beginPath();
                    ctxGrid.moveTo(0, j);
                    ctxGrid.lineTo(256, j);
                    ctxGrid.stroke();
                }

                const gridTexture = new THREE.CanvasTexture(canvasGrid);
                const globeMaterial = new THREE.MeshBasicMaterial({
                    map: gridTexture,
                    transparent: true,
                    opacity: 0.9
                });

                globe3D = new THREE.Mesh(globeGeometry, globeMaterial);
                scene3D.add(globe3D);

                pointSpikesGroup = new THREE.Group();
                globe3D.add(pointSpikesGroup);

                // Add mouse & touch interaction handlers
                const dom = renderer3D.domElement;
                dom.addEventListener('mousedown', onMouseDown3D);
                dom.addEventListener('mousemove', onMouseMove3D);
                window.addEventListener('mouseup', onMouseUp3D);

                dom.addEventListener('touchstart', onTouchStart3D, { passive: true });
                dom.addEventListener('touchmove', onTouchMove3D, { passive: true });
                dom.addEventListener('touchend', onTouchEnd3D, { passive: true });

                sync3DPins();
            } catch (error) {
                console.warn("WebGL system failed initialization:", error);
                disable3DInterface();
            }
        }

        function disable3DInterface() {
            const btn3D = document.getElementById('btn-view-3d');
            if (btn3D) {
                btn3D.disabled = true;
                btn3D.classList.add('opacity-40', 'cursor-not-allowed', 'hover:border-zinc-800', 'hover:text-zinc-400');
                btn3D.title = "WebGL no disponible";
                btn3D.onclick = null;
            }
            is3DModeActive = false;
        }

        function sync3DPins() {
            if (!pointSpikesGroup) return;
            while(pointSpikesGroup.children.length > 0) {
                pointSpikesGroup.remove(pointSpikesGroup.children[0]);
            }

            incidentEvents.forEach(evt => {
                let col = 0x06b6d4;
                if (evt.severity === 'WARNING') col = 0xf59e0b;
                if (evt.severity === 'CRITICAL') col = 0xef4444;

                const pinGeo = new THREE.ConeGeometry(1.2, 8, 4); 
                pinGeo.translate(0, 4, 0);
                pinGeo.rotateX(Math.PI / 2);

                const pinMat = new THREE.MeshBasicMaterial({
                    color: col,
                    transparent: true,
                    opacity: 0.8
                });

                const pinMesh = new THREE.Mesh(pinGeo, pinMat);

                const rad = 60;
                const phi = (90 - evt.lat) * (Math.PI / 180);
                const theta = (evt.lng + 180) * (Math.PI / 180);

                pinMesh.position.x = -(rad * Math.sin(phi) * Math.sin(theta));
                pinMesh.position.y = (rad * Math.cos(phi));
                pinMesh.position.z = (rad * Math.sin(phi) * Math.cos(theta));

                pinMesh.lookAt(new THREE.Vector3(0,0,0));
                pointSpikesGroup.add(pinMesh);
            });
        }

        function rotate3DGlobeTo(lat, lng) {
            if (!is3DModeActive || !globe3D) return;
            const phi = (90 - lat) * (Math.PI / 180);
            const theta = (lng + 180) * (Math.PI / 180);
            orbitAngles.theta = theta - Math.PI / 2;
            orbitAngles.phi = phi;
        }

        function onMouseDown3D(e) {
            isDraggingGlobe = true;
            previousMousePosition = { x: e.clientX, y: e.clientY };
        }

        function onMouseMove3D(e) {
            if (!isDraggingGlobe) return;
            const deltaX = e.clientX - previousMousePosition.x;
            const deltaY = e.clientY - previousMousePosition.y;

            orbitAngles.theta += deltaX * 0.005;
            orbitAngles.phi -= deltaY * 0.005;
            orbitAngles.phi = Math.max(0.1, Math.min(Math.PI - 0.1, orbitAngles.phi));

            previousMousePosition = { x: e.clientX, y: e.clientY };
        }

        function onMouseUp3D() {
            isDraggingGlobe = false;
        }

        function onTouchStart3D(e) {
            if(e.touches.length === 1) {
                isDraggingGlobe = true;
                previousMousePosition = { x: e.touches[0].clientX, y: e.touches[0].clientY };
            }
        }

        function onTouchMove3D(e) {
            if(!isDraggingGlobe || e.touches.length !== 1) return;
            const deltaX = e.touches[0].clientX - previousMousePosition.x;
            const deltaY = e.touches[0].clientY - previousMousePosition.y;

            orbitAngles.theta += deltaX * 0.005;
            orbitAngles.phi -= deltaY * 0.005;
            orbitAngles.phi = Math.max(0.1, Math.min(Math.PI - 0.1, orbitAngles.phi));

            previousMousePosition = { x: e.touches[0].clientX, y: e.touches[0].clientY };
        }

        function onTouchEnd3D() {
            isDraggingGlobe = false;
        }

        function animate3D() {
            if (!is3DModeActive || !renderer3D || !scene3D || !camera3D) return;
            requestAnimationFrame(animate3D);

            if (!isDraggingGlobe && globe3D) {
                globe3D.rotation.y += 0.0004; 
            }

            const radius = 180;
            camera3D.position.x = radius * Math.sin(orbitAngles.phi) * Math.sin(orbitAngles.theta);
            camera3D.position.y = radius * Math.cos(orbitAngles.phi);
            camera3D.position.z = radius * Math.sin(orbitAngles.phi) * Math.cos(orbitAngles.theta);
            
            camera3D.lookAt(scene3D.position);

            document.getElementById('cam-x').innerText = camera3D.position.x.toFixed(1);
            document.getElementById('cam-y').innerText = camera3D.position.y.toFixed(1);

            renderer3D.render(scene3D, camera3D);
        }

        function setViewMode(is3D) {
            if (is3D && !renderer3D) {
                writeLog('Visor 3D no disponible.', 'warning');
                return;
            }
            playTacticalSound('click');
            is3DModeActive = is3D;
            
            const mapEl = document.getElementById('map');
            const container3DEl = document.getElementById('container-3d');
            const btn2D = document.getElementById('btn-view-2d');
            const btn3D = document.getElementById('btn-view-3d');

            if (is3D) {
                mapEl.classList.add('hidden');
                container3DEl.classList.remove('hidden');
                btn3D.className = "flex-1 py-1 px-3 border border-cyan-500 bg-cyan-950/20 text-cyan-400 font-semibold rounded-md text-[10px] shadow-sm transition-colors";
                btn2D.className = "flex-1 py-1 px-3 border border-zinc-800 bg-zinc-950 hover:border-cyan-500/40 text-zinc-500 hover:text-cyan-400 font-semibold rounded-md text-[10px] shadow-sm transition-colors";
                
                const canvasW = container3DEl.clientWidth;
                const canvasH = container3DEl.clientHeight;
                renderer3D.setSize(canvasW, canvasH);
                camera3D.aspect = canvasW / canvasH;
                camera3D.updateProjectionMatrix();

                sync3DPins();
                animate3D();
                writeLog('Entorno WebGL 3D Activado.', 'info');
            } else {
                container3DEl.classList.add('hidden');
                mapEl.classList.remove('hidden');
                btn2D.className = "flex-1 py-1 px-3 border border-cyan-500 bg-cyan-950/20 text-cyan-400 font-semibold rounded-md text-[10px] shadow-sm transition-colors";
                btn3D.className = "flex-1 py-1 px-3 border border-zinc-800 bg-zinc-950 hover:border-cyan-500/40 text-zinc-500 hover:text-cyan-400 font-semibold rounded-md text-[10px] shadow-sm transition-colors";
                
                setTimeout(() => {
                    map.invalidateSize();
                }, 100);
                writeLog('Entorno Cartográfico 2D Activado.', 'info');
            }
        }

        async function traceIP() {
            playTacticalSound('click');
            const ip = document.getElementById('osint-ip-input').value.trim();
            if (!ip) return;

            writeLog(`Triangulando geolocalización IP segura para: ${ip}...`, 'info');
            
            try {
                // Call Python server endpoint
                const res = await fetch('/api/trace_ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: ip })
                });
                const data = await res.json();

                if (data.error) {
                    writeLog(`Fallo en resolución IP: ${data.error}`, 'warning');
                    return;
                }

                writeLog(`IP geolocalizada con éxito en: ${data.city || 'Ubicación remota'}.`, 'success');

                const newEvt = {
                    id: `ip-evt-${Date.now()}`,
                    title: `Nodo de Red Identificado: ${data.ip}`,
                    category: 'SIGINT',
                    severity: 'INFO',
                    locationName: `${data.city}, ${data.country_name}`,
                    lat: data.latitude,
                    lng: data.longitude,
                    time: new Date().toUTCString().split(' ')[4] + ' UTC',
                    desc: `Nodo de Red OSINT. Proveedor: ${data.isp || 'No registrado'}. Org: ${data.org || 'Privada'}. ASN: ${data.asn || 'AS-Local'}.`,
                    sensorCode: `OSINT-IP-${Math.floor(Math.random()*900+100)}`,
                    sources: [{ uri: `https://who.is/whois-ip/ip-address/${data.ip}`, title: 'Whois' }]
                };

                incidentEvents.unshift(newEvt);
                refreshMapMarkers();
                panToIncident(data.latitude, data.longitude, newEvt.id);
                playTacticalSound('success');

            } catch (err) {
                writeLog(`Error crítico de conexión al servidor de rastreo IP.`, 'critical');
            }
        }

        async function processExifImage(event) {
            const file = event.target.files[0];
            if (!file) return;

            writeLog(`Enviando archivo binario a la API de Python: ${file.name}...`, 'info');
            playTacticalSound('click');

            const formData = new FormData();
            formData.append('file', file);

            try {
                const res = await fetch('/api/exif_parse', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();

                if (data.error) {
                    writeLog(`Fallo forense: ${data.error}`, 'warning');
                    return;
                }

                writeLog(`Éxito forense: Ubicación GPS extraída del EXIF.`, 'success');
                
                const newEvt = {
                    id: `exif-evt-${Date.now()}`,
                    title: `Imagen Geolocalizada (OSINT Forense)`,
                    category: 'IMINT',
                    severity: 'WARNING',
                    locationName: 'Ubicación Física de Captura',
                    lat: data.latitude,
                    lng: data.longitude,
                    time: new Date().toUTCString().split(' ')[4] + ' UTC',
                    desc: `Metadata de la imagen recuperada con coordenadas GPS incrustadas en el bloque EXIF nativo.`,
                    sensorCode: `OSINT-EXIF-IMG`,
                    sources: [{ uri: '#', title: 'EXIF File Block' }]
                };

                incidentEvents.unshift(newEvt);
                refreshMapMarkers();
                panToIncident(data.latitude, data.longitude, newEvt.id);
                playTacticalSound('success');

            } catch (err) {
                writeLog('Excepción al conectar con el motor EXIF de Python.', 'critical');
            }
        }

        function updateDorkPreview() {
            const dorkType = document.getElementById('dork-type').value;
            const preview = document.getElementById('dork-preview');

            let queryStr = '';
            if (dorkType === 'cams') {
                queryStr = 'inurl:"viewerframe?mode=motion" | intitle:"Live View / - AXIS"';
            } else if (dorkType === 'docs') {
                queryStr = 'filetype:pdf "CONFIDENTIAL" "NOT FOR PUBLIC"';
            } else if (dorkType === 'admin') {
                queryStr = 'intitle:"Admin Dashboard" | inurl:admin/login.php';
            } else if (dorkType === 'logins') {
                queryStr = 'inurl:login.html filetype:txt "password="';
            }

            preview.innerText = queryStr;
        }

        function launchDork() {
            playTacticalSound('click');
            const query = document.getElementById('dork-preview').innerText;
            const url = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
            window.open(url, '_blank');
            writeLog(`Auditando Google Dork en una ventana externa.`, 'info');
        }

        async function reconUsername() {
            playTacticalSound('click');
            const username = document.getElementById('osint-username').value.trim();
            if(!username) return;

            writeLog(`Ejecutando escaneo activo de perfiles en Python para: ${username}...`, 'info');
            document.getElementById('username-results').classList.remove('hidden');

            const platforms = ['github', 'twitter', 'reddit', 'tiktok'];
            platforms.forEach(p => {
                const el = document.getElementById(`recon-res-${p}`);
                if (el) {
                    el.querySelector('.status-indicator').innerText = "ESCANEO...";
                    el.querySelector('.status-indicator').className = "status-indicator text-amber-500 font-bold animate-pulse";
                }
            });

            try {
                const res = await fetch('/api/recon_username', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username })
                });
                const data = await res.json();

                platforms.forEach(p => {
                    const el = document.getElementById(`recon-res-${p}`);
                    if (el && data[p]) {
                        const statusSpan = el.querySelector('.status-indicator');
                        if (data[p].exists) {
                            statusSpan.innerText = "DETECTADO";
                            statusSpan.className = "status-indicator text-emerald-400 font-bold";
                            el.style.cursor = "pointer";
                            el.onclick = () => window.open(data[p].url, '_blank');
                        } else {
                            statusSpan.innerText = "LIBRE";
                            statusSpan.className = "status-indicator text-zinc-600";
                            el.style.cursor = "default";
                            el.onclick = null;
                        }
                    }
                });

                writeLog('Escaneo de alias por Python finalizado con éxito.', 'success');
                playTacticalSound('success');

            } catch (err) {
                writeLog('Fallo al consultar la API de escaneo de alias.', 'critical');
            }
        }

        function togglePerimeterDrawTool() {
            playTacticalSound('click');
            perimeterToolActive = !perimeterToolActive;
            
            const btnText = document.getElementById('perimeter-btn-text');
            const btn = document.getElementById('btn-perimeter-tool');

            if (perimeterToolActive) {
                btnText.innerText = "CANCELAR SELECCIÓN";
                btn.classList.add('bg-red-950/20', 'border-red-500/50', 'text-red-400');
                btn.classList.remove('bg-cyan-950/5', 'border-cyan-500/20', 'text-cyan-400');
                writeLog('Herramienta Perímetro Activa. Haz clic en el mapa táctico.', 'info');
            } else {
                btnText.innerText = "Activar Selección (Mapa)";
                btn.classList.remove('bg-red-950/20', 'border-red-500/50', 'text-red-400');
                btn.classList.add('bg-cyan-950/5', 'border-cyan-500/20', 'text-cyan-400');
            }
        }

        async function executePerimeterAnalysis(lat, lng) {
            togglePerimeterDrawTool();
            playTacticalSound('ping');

            writeLog(`Fijando sector en coordenadas: ${lat.toFixed(5)}, ${lng.toFixed(5)}`, 'info');

            if (activePerimeterCircle) {
                map.removeLayer(activePerimeterCircle);
            }

            activePerimeterCircle = L.circle([lat, lng], {
                radius: 500,
                color: '#27272a',
                fillColor: '#06b6d4',
                fillOpacity: 0.08,
                weight: 1,
                dashArray: '3, 3'
            }).addTo(map);

            map.setView([lat, lng], 16);

            const hud = document.getElementById('perimeter-results-hud');
            hud.classList.remove('hidden');

            document.getElementById('gemma-target-coords').innerText = `LAT: ${lat.toFixed(5)} | LNG: ${lng.toFixed(5)}`;
            document.getElementById('gemma-pop-calc').innerText = "PROCESANDO...";
            document.getElementById('gemma-homes-calc').innerText = "PROCESANDO...";
            document.getElementById('gemma-psychological-box').innerText = "Estudiando georreferencias y analizando redes de prensa local...";

            let cityRegion = "Zona de Transmisión";
            try {
                const geoUrl = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&zoom=18`;
                const geoRes = await fetch(geoUrl, {
                    headers: { 'Accept-Language': 'es' }
                });
                const geoData = await geoRes.json();
                if (geoData && geoData.address) {
                    cityRegion = geoData.address.suburb || geoData.address.neighbourhood || geoData.address.city || geoData.address.town || "Área Georreferenciada";
                    writeLog(`Firma Geográfica Confirmada: ${cityRegion}`, 'success');
                }
            } catch(e) {
                console.log("No se pudo obtener la geocodificación inversa.");
            }

            const apiKey = document.getElementById('gemma-key').value.trim();
            if (apiKey) {
                writeLog('Invocando motor neural Gemma con Google Search Grounding...', 'info');
                try {
                    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
                    
                    const prompt = `Analyze a strict geographic area with a 500-meter radius around Coordinates: Lat ${lat}, Lng ${lng} (${cityRegion}).
                    Use Google Search to find actual local events, social issues, municipal updates, or natural factors around these coordinates.
                    Return ONLY a JSON response matching this schema:
                    {
                      "estimatedPopulation": integer,
                      "estimatedHomes": integer,
                      "moraleIndex": integer,
                      "moraleStatus": "STABLE" | "LOW" | "HIGH" | "CRITICAL",
                      "psychologicalAnalysis": "A detailed Spanish text explaining the collective psychology, worries, resilience, and general public mood based on recent events in this 500m area."
                    }`;

                    const res = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            contents: [{ parts: [{ text: prompt }] }],
                            tools: [{ "google_search": {} }],
                            generationConfig: {
                                responseMimeType: "application/json"
                            }
                        })
                    });

                    const data = await res.json();
                    const textResponse = data.candidates[0].content.parts[0].text;
                    const cleanJson = JSON.parse(textResponse.replace(/```json|```/g, '').trim());

                    document.getElementById('gemma-pop-calc').innerText = `${cleanJson.estimatedPopulation} Habs`;
                    document.getElementById('gemma-homes-calc').innerText = `${cleanJson.estimatedHomes} Hogares`;
                    document.getElementById('gemma-moral-text').innerText = `${cleanJson.moraleStatus} (${cleanJson.moraleIndex}%)`;
                    document.getElementById('gemma-moral-bar').style.width = `${cleanJson.moraleIndex}%`;
                    document.getElementById('gemma-psychological-box').innerText = cleanJson.psychologicalAnalysis;

                    writeLog('Diagnóstico psicológico regional completado.', 'success');
                    playTacticalSound('success');

                } catch (err) {
                    writeLog('Excepción de conexión con Gemma. Cambiando a modelo heurístico local.', 'warning');
                    runLocalFallbackAnalysis(lat, lng, cityRegion);
                }
            } else {
                writeLog('No se detectó una API Key para Gemma. Ejecutando análisis heurístico local...', 'info');
                setTimeout(() => {
                    runLocalFallbackAnalysis(lat, lng, cityRegion);
                }, 800);
            }
        }

        function runLocalFallbackAnalysis(lat, lng, cityRegion) {
            const seed = Math.abs(Math.sin(lat) * Math.cos(lng));
            const population = Math.floor(seed * 4800) + 200;
            const homes = Math.floor(population / 3.2);
            const morale = Math.floor(seed * 50) + 40;
            
            let status = 'ESTABLE';
            let color = 'text-emerald-400';
            let diagnostic = '';

            if (morale < 50) {
                status = 'BAJA / ALERTA';
                color = 'text-amber-500';
                diagnostic = `La población de ${cityRegion} muestra niveles de tensión causados por volatilidad del entorno local, factores ambientales o estructurales en un radio de 500 metros. Existe preocupación latente, pero el tejido comunitario conserva resiliencia.`;
            } else if (morale < 75) {
                status = 'ESTABLE';
                color = 'text-cyan-400';
                diagnostic = `En el sector georreferenciado de ${cityRegion} prevalece un ánimo neutral y estable. No se registran incidentes geológicos o climáticos severos recientes. El comportamiento social es adaptativo con un nivel bajo de fricción.`;
            } else {
                status = 'ÓPTIMA';
                color = 'text-emerald-400';
                diagnostic = `Estudio psicológico en ${cityRegion} revela un ambiente altamente favorable en el cuadrante de 500 metros. Ausencia de reportes críticos y excelentes índices de habitabilidad se traducen en una moral pública sólida.`;
            }

            document.getElementById('gemma-pop-calc').innerText = `${population} Habs`;
            document.getElementById('gemma-homes-calc').innerText = `${homes} Hogares`;
            document.getElementById('gemma-moral-text').innerText = `${status} (${morale}%)`;
            document.getElementById('gemma-moral-text').className = `font-bold ${color}`;
            document.getElementById('gemma-moral-bar').style.width = `${morale}%`;
            document.getElementById('gemma-psychological-box').innerText = diagnostic;

            writeLog(`Diagnóstico de Contingencia completado para ${cityRegion}.`, 'success');
            playTacticalSound('success');
        }

        function copyCurrentCoords() {
            const coordsText = document.getElementById('gemma-target-coords').innerText;
            const textarea = document.createElement('textarea');
            textarea.value = coordsText;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            writeLog('Coordenadas copiadas al portapapeles.', 'success');
            playTacticalSound('click');
        }

        async function handleSearch() {
            const query = document.getElementById('map-search').value.trim();
            if (!query) {
                writeLog('Escriba un territorio para iniciar la ingestión.', 'warning');
                return;
            }

            const loader = document.getElementById('osint-loader');
            const loaderStatus = document.getElementById('osint-loader-status');
            
            loader.classList.remove('hidden');
            playTacticalSound('alarm');

            loaderStatus.innerText = `Geolocalizando ${query} en los servidores globales...`;

            try {
                const geocodeUrl = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(query)}&limit=1`;
                const geoRes = await fetch(geocodeUrl);
                const geoData = await geoRes.json();

                if (!geoData || geoData.length === 0) {
                    writeLog(`No se pudo geolocalizar la región: ${query}`, 'warning');
                    loader.classList.add('hidden');
                    return;
                }

                const targetLat = parseFloat(geoData[0].lat);
                const targetLng = parseFloat(geoData[0].lon);
                const displayName = geoData[0].display_name;

                loaderStatus.innerText = `Enlazando estación con el objetivo...`;
                
                if (is3DModeActive) {
                    rotate3DGlobeTo(targetLat, targetLng);
                } else {
                    map.setView([targetLat, targetLng], 8, { animate: true });
                }

                drawGeodesicLink(targetLat, targetLng);

                loaderStatus.innerText = `Consultando noticieros y reportes en vivo para ${query}...`;
                
                const apiKey = document.getElementById('gemma-key').value.trim();
                if (apiKey) {
                    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
                    
                    const prompt = `Search for 1 or 2 real-world news, emergency alerts, or events occurring in "${displayName}" (Coords: ${targetLat}, ${targetLng}).
                    Use Google Search and return a strict JSON array matching this exact schema:
                    [
                      {
                        "title": "Clear news title",
                        "category": "seguridad" | "climático" | "geológico" | "ambiental",
                        "severity": "CRITICAL" | "WARNING" | "INFO",
                        "lat": float,
                        "lng": float,
                        "desc": "Short summary of what is happening based on the latest hours.",
                        "sensorCode": "OSINT-NEWS",
                        "sourceUrl": "The real news URL you found",
                        "sourceTitle": "Name of the news portal"
                      }
                    ]`;

                    const res = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            contents: [{ parts: [{ text: prompt }] }],
                            tools: [{ "google_search": {} }],
                            generationConfig: { responseMimeType: "application/json" }
                        })
                    });

                    const data = await res.json();
                    const textRes = data.candidates[0].content.parts[0].text;
                    const listEvts = JSON.parse(textRes.replace(/```json|```/g, '').trim());

                    listEvts.forEach(item => {
                        incidentEvents.unshift({
                            id: `gemma-news-${Date.now()}-${Math.random()}`,
                            title: item.title,
                            category: item.category,
                            severity: item.severity,
                            locationName: query,
                            lat: item.lat || targetLat,
                            lng: item.lng || targetLng,
                            time: new Date().toUTCString().split(' ')[4] + ' UTC',
                            desc: item.desc,
                            sensorCode: item.sensorCode,
                            sources: [{ uri: item.sourceUrl, title: item.sourceTitle }]
                        });
                    });

                    writeLog(`Ingesta exitosa: se cargaron ${listEvts.length} reportes reales en ${query}.`, 'success');

                } else {
                    // Fallback local mock simulation if Gemma API key is absent
                    setTimeout(() => {
                        const fallEvt = {
                            id: `fall-news-${Date.now()}`,
                            title: `Operación de Monitoreo OSINT: ${query}`,
                            category: 'seguridad',
                            severity: 'WARNING',
                            locationName: displayName,
                            lat: targetLat + (Math.random() - 0.5) * 0.1,
                            lng: targetLng + (Math.random() - 0.5) * 0.1,
                            time: new Date().toUTCString().split(' ')[4] + ' UTC',
                            desc: `Se ha sintonizado la escucha radiofónica y de fuentes abiertas de prensa en la de ${query}. Canal de contingencia activo.`,
                            sensorCode: `OSINT-MON-${Math.floor(Math.random()*900+100)}`,
                            sources: [
                                { uri: 'https://news.google.com', title: 'Google News' },
                                { uri: 'https://www.reuters.com', title: 'Reuters' }
                            ]
                        };
                        incidentEvents.unshift(fallEvt);
                        writeLog(`Ingesta completada: Monitoreo establecido en ${query}.`, 'success');
                    }, 1000);
                }

                setTimeout(() => {
                    refreshMapMarkers();
                    loader.classList.add('hidden');
                    playTacticalSound('success');
                }, 1100);

            } catch (err) {
                writeLog('Error crítico en el proceso de Ingestión Geográfica.', 'critical');
                loader.classList.add('hidden');
            }
        }

        function initTelemetryChart() {
            const ctx = document.getElementById('telemetry-chart').getContext('2d');
            telemetryChartInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: Array(20).fill(''),
                    datasets: [{
                        label: 'Nivel Telemetría Red',
                        data: telemetryDataPoints,
                        borderColor: '#06b6d4',
                        borderWidth: 1,
                        pointRadius: 0,
                        fill: true,
                        backgroundColor: 'rgba(6, 182, 212, 0.02)',
                        tension: 0.2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { display: false },
                        y: {
                            min: 0,
                            max: 100,
                            ticks: { display: false },
                            grid: { color: 'rgba(39, 39, 42, 0.15)' }
                        }
                    }
                }
            });
        }

        function updateTelemetryData() {
            const lastVal = telemetryDataPoints[telemetryDataPoints.length - 1];
            let newVal = lastVal + (Math.random() - 0.5) * 15;
            newVal = Math.max(10, Math.min(90, newVal));

            telemetryDataPoints.shift();
            telemetryDataPoints.push(newVal);

            if (telemetryChartInstance) {
                telemetryChartInstance.data.datasets[0].data = telemetryDataPoints;
                telemetryChartInstance.update();
            }

            document.getElementById('packet-status').innerText = `${Math.floor(700 + Math.random()*250)} kb/s`;
        }

        function initCCTV() {
            cctvCanvas = document.getElementById('cctv-canvas');
            cctvCtx = cctvCanvas.getContext('2d');
            cctvCanvas.width = 160;
            cctvCanvas.height = 90;
            setInterval(drawCCTVFrame, 125);
        }

        function setCameraMode(mode) {
            playTacticalSound('click');
            cctvMode = mode;
            
            const btnT = document.getElementById('btn-cam-thermal');
            const btnR = document.getElementById('btn-cam-radar');

            if (mode === 'thermal') {
                btnT.className = "flex-1 py-1 bg-cyan-950/20 text-cyan-400 border border-cyan-500/20 text-[9px] font-semibold rounded";
                btnR.className = "flex-1 py-1 hover:bg-zinc-800 text-zinc-500 text-[9px] font-semibold rounded transition-colors";
            } else {
                btnR.className = "flex-1 py-1 bg-cyan-950/20 text-cyan-400 border border-cyan-500/20 text-[9px] font-semibold rounded";
                btnT.className = "flex-1 py-1 hover:bg-zinc-800 text-zinc-500 text-[9px] font-semibold rounded transition-colors";
            }
        }

        function drawCCTVFrame() {
            if (!cctvCtx || !rightSidebarOpen) return; 
            cctvFrame++;

            const w = cctvCanvas.width;
            const h = cctvCanvas.height;

            cctvCtx.fillStyle = '#09090b';
            cctvCtx.fillRect(0, 0, w, h);

            if (cctvMode === 'thermal') {
                const grad = cctvCtx.createRadialGradient(
                    w / 2 + Math.sin(cctvFrame / 10) * 15,
                    h / 2 + Math.cos(cctvFrame / 8) * 8,
                    2,
                    w / 2 + Math.sin(cctvFrame / 10) * 15,
                    h / 2 + Math.cos(cctvFrame / 8) * 8,
                    20
                );
                grad.addColorStop(0, '#f97316');
                grad.addColorStop(0.6, '#e11d48');
                grad.addColorStop(1, '#09090b');

                cctvCtx.fillStyle = grad;
                cctvCtx.fillRect(0, 0, w, h);

            } else {
                cctvCtx.strokeStyle = 'rgba(6, 182, 212, 0.1)';
                cctvCtx.lineWidth = 0.5;
                cctvCtx.beginPath();
                cctvCtx.arc(w/2, h/2, 15, 0, Math.PI * 2);
                cctvCtx.arc(w/2, h/2, 30, 0, Math.PI * 2);
                cctvCtx.stroke();

                const angle = (cctvFrame % 30) * (Math.PI / 15);
                cctvCtx.strokeStyle = 'rgba(6, 182, 212, 0.4)';
                cctvCtx.lineWidth = 1;
                cctvCtx.beginPath();
                cctvCtx.moveTo(w/2, h/2);
                cctvCtx.lineTo(w/2 + Math.cos(angle) * 35, h/2 + Math.sin(angle) * 35);
                cctvCtx.stroke();

                if ((cctvFrame % 30) < 10) {
                    cctvCtx.fillStyle = 'rgba(239, 68, 68, 0.7)';
                    cctvCtx.beginPath();
                    cctvCtx.arc(w/2 + 15, h/2 - 8, 2, 0, Math.PI * 2);
                    cctvCtx.fill();
                }
            }

            if (cctvFrame % 8 === 0) {
                document.getElementById('cctv-fps').innerText = `${Math.floor(7 + Math.random() * 2)} FPS`;
            }
        }
    </script>
</body>
</html>"""

if __name__ == "__main__":
    def open_browser():
        webbrowser.open_new("http://127.0.0.1:5000")

    # Start a background timer to open browser automatically once Flask loads
    threading.Timer(1.2, open_browser).start()
    
    # Run secure local web app deployment
    app.run(host="127.0.0.1", port=5000, debug=False)
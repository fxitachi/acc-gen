from flask import Flask, jsonify, request
import base64
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import MajorLoginReq_pb2
import MajorLoginRes_pb2
import jwt_generator_pb2
import login_pb2
import my_pb2
import output_pb2
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import RequestException
from google.protobuf import json_format, message
from google.protobuf.message import Message
import threading
from protobuf_decoder.protobuf_decoder import Parser

# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

app = Flask(__name__)

# -------------------------------
# Funções auxiliares
# -------------------------------

def carregar_tokens_existentes(token_file):
    """Carrega tokens existentes de um arquivo JSON remoto"""
    try:
        url = f"https://scvirtual.alphi.media/botsistem/sendlike/{token_file}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        tokens = response.json()
        
        # Criar mapa por LOGIN (que corresponde aos UIDs do acc.json)
        token_map = {}
        for token_data in tokens:
            login = token_data.get("login")
            if login:
                token_map[str(login)] = token_data  # Mapeia pelo login
        
        return token_map
    except requests.RequestException as e:
        print(f"Erro ao carregar {token_file}: {e}")
        return {}

def decode_jwt(token):
    try:
        # Verificar se é um token JWT válido
        if not token or len(token.split(".")) != 3:
            print("❌ Token não é um JWT válido")
            return None
            
        payload_part = token.split(".")[1]
        padded = payload_part + "=" * (-len(payload_part) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        decoded_str = decoded_bytes.decode("utf-8")
        payload = json.loads(decoded_str)
        
        # Debug mais detalhado
        print(f"✅ JWT decodificado - UID: {payload.get('account_id')}, Login: {payload.get('external_uid')}, Exp: {payload.get('exp')}")
        return payload
        
    except Exception as e:
        print(f"❌ Erro ao decodificar JWT: {e}. Token (início): {token[:50]}...")
        return None

def fetch_attversion():
    url = "https://raw.githubusercontent.com/minimalsend/release/refs/heads/main/version.json"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        def buscar_attversion(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if k == "attversion":
                        return v
                    resultado = buscar_attversion(v)
                    if resultado is not None:
                        return resultado
            elif isinstance(d, list):
                for item in d:
                    resultado = buscar_attversion(item)
                    if resultado is not None:
                        return resultado
            return None
        
        attversion = buscar_attversion(data)
        if attversion is not None:
            return attversion
        else:
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição: {e}")
    except ValueError:
        print("Erro ao decodificar o JSON.")

def get_token(password, uid, max_retries=3):
    """
    Obtém token de autenticação da API Garena com proteção contra rate limiting.
    """
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "authority": "100067.connect.garena.com",
        "method": "GET",
        "scheme": "https",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "cache-control": "max-age=0",
        "priority": "u=0, i",
        "sec-ch-ua": '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }

    for attempt in range(max_retries):
        try:
            if attempt > 0:
                wait_time = min((2 ** attempt) + random.uniform(0, 1), 10)
                print(f"Tentativa {attempt + 1}/{max_retries}. Aguardando {wait_time:.2f} segundos...")
                time.sleep(wait_time)

            res = requests.post(url, headers=headers, data=data, timeout=15)
            
            if res.status_code == 200:
                token_json = res.json()
                if "access_token" in token_json and "open_id" in token_json:
                    return token_json
                else:
                    print("Resposta inválida: Token ou OpenID ausente")
                    continue
            
            elif res.status_code == 429:
                retry_after = res.headers.get('Retry-After', 5)
                print(f"Rate limit atingido. Servidor pede para esperar {retry_after} segundos.")
                time.sleep(float(retry_after))
                continue
            
            else:
                print(f"Erro HTTP {res.status_code}: {res.text}")
                continue

        except RequestException as e:
            print(f"Erro na requisição (tentativa {attempt + 1}): {str(e)}")
            continue
        
        except ValueError as e:
            print(f"Erro ao decodificar JSON (tentativa {attempt + 1}): {str(e)}")
            continue

    print(f"Falha após {max_retries} tentativas.")
    return None

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def autenticar(usuario):
    try:
        uid = usuario.get('uid')
        password = usuario.get('password')

        if not uid or not password:
            raise ValueError("❌ Parâmetros inválidos: 'uid' e 'password' são obrigatórios.")

        versionob = fetch_attversion()
        token_data = get_token(password, uid)

        if not token_data:
            raise ValueError("❌ Falha: get_token() retornou None")

        access_token = token_data.get('access_token')
        open_id = token_data.get('open_id')

        if not access_token or not open_id:
            raise ValueError("❌ Falha: access_token ou open_id ausentes")

        # --- Monta objeto MajorLogin ---
        major_login = MajorLoginReq_pb2.MajorLogin()
        major_login.event_time = "2025-06-04 19:48:07"
        major_login.game_name = "free fire"
        major_login.platform_id = 1
        major_login.client_version = "2.112.2"
        major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
        major_login.system_hardware = "Handheld"
        major_login.telecom_operator = "Verizon"
        major_login.network_type = "WIFI"
        major_login.screen_width = 1920
        major_login.screen_height = 1080
        major_login.screen_dpi = "280"
        major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
        major_login.memory = 3003
        major_login.gpu_renderer = "Adreno (TM) 640"
        major_login.gpu_version = "OpenGL ES 3.1 v1.46"
        major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
        major_login.client_ip = "223.191.51.89"
        major_login.language = "en"
        major_login.open_id = open_id
        major_login.open_id_type = "4"
        major_login.device_type = "Handheld"

        memory_available = major_login.memory_available
        memory_available.version = 55
        memory_available.hidden_value = 81

        major_login.access_token = access_token
        major_login.platform_sdk_id = 1
        major_login.network_operator_a = "Verizon"
        major_login.network_type_a = "WIFI"
        major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
        major_login.external_storage_total = 36235
        major_login.external_storage_available = 31335
        major_login.internal_storage_total = 2519
        major_login.internal_storage_available = 703
        major_login.game_disk_storage_available = 25010
        major_login.game_disk_storage_total = 26628
        major_login.external_sdcard_avail_storage = 32992
        major_login.external_sdcard_total_storage = 36235
        major_login.login_by = 3
        major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
        major_login.reg_avatar = 1
        major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
        major_login.channel_type = 3
        major_login.cpu_type = 2
        major_login.cpu_architecture = "64"
        major_login.client_version_code = "2019117863"
        major_login.graphics_api = "OpenGLES2"
        major_login.supported_astc_bitset = 16383
        major_login.login_open_id_type = 4
        major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
        major_login.loading_time = 13564
        major_login.release_channel = "android"
        major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
        major_login.android_engine_init_flag = 110009
        major_login.if_push = 1
        major_login.is_vpn = 1
        major_login.origin_platform_type = "4"
        major_login.primary_platform_type = "4"

        # --- Encripta e envia MajorLogin ---
        serialized_data = major_login.SerializeToString()
        encrypted_data = aes_cbc_encrypt(AES_KEY, AES_IV, serialized_data)
        edata = binascii.hexlify(encrypted_data).decode()

        url = "https://loginbp.ggwhitehawk.com/MajorLogin"
        headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB51"
        }
        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)

        if response.status_code != 200:
            raise ValueError(f"HTTP {response.status_code} - {response.reason}")

        # --- Parse da resposta MajorLogin ---
        login_res = MajorLoginRes_pb2.MajorLoginRes()
        login_res.ParseFromString(response.content)
        print(login_res)
        # --- Segundo request: GetLoginData ---
        login_req = login_pb2.LoginReq()
        login_req.account_id = login_res.account_id
        serialized_login = login_req.SerializeToString()
        encrypted_login = aes_cbc_encrypt(AES_KEY, AES_IV, serialized_login)
        login_hex = binascii.hexlify(encrypted_login).decode()

        login_url = "https://loginbp.common.ggbluefox.com/GetLoginData"
        login_response = requests.post(login_url, data=bytes.fromhex(login_hex), headers=headers, verify=False)

        nickname = ""
        region = ""
        level = 0
        exp = 0
        create_at = 0

        if login_response.status_code == 200:
            try:
                login_info = login_pb2.LoginReq()
                login_info.ParseFromString(login_response.content)
                nickname = getattr(login_info, 'nickname', '')
                region = getattr(login_info, 'region', '')
                level = getattr(login_info, 'level', 0)
                exp = getattr(login_info, 'exp', 0)
                create_at = getattr(login_info, 'create_at', 0)
            except Exception:
                pass

        # --- Parse JWT / Token ---
        example_msg = jwt_generator_pb2.Garena_420()
        example_msg.ParseFromString(response.content)
        response_dict = parse_response(str(example_msg))

        BASE64_TOKEN = response_dict.get("token", "")
        if not BASE64_TOKEN:
            raise ValueError("Estrutura de resposta inválida ou token ausente")

        print(f"[{uid}] ✅ Token gerado com sucesso")

        return {
            "uid": uid,
            "nickname": nickname,
            "region": region,
            "level": level,
            "exp": exp,
            "create_at": create_at,
            "token": BASE64_TOKEN
        }

    except Exception as e:
        raise ValueError(f"Token generation failed: {str(e)}")


def parse_response(content: str) -> dict:
    """Parse protobuf response into dictionary."""
    return dict(
        line.split(":", 1)
        for line in content.split("\n")
        if ":" in line
    )
def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        if result.wire_type == "string":
            field_data['data'] = result.data
        if result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict


def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"{red}{bold}error {e}")
        return None

def token_expirado(token, tolerancia=300):
    payload = decode_jwt(token)
    if not payload:
        print("ℹ️ Token não é JWT, mantendo como válido.")
        return False  
    
    exp = payload.get("exp")
    if exp is None:
        print("⚠️ JWT sem campo exp → tratando como expirado.")
        return True

    agora = int(time.time())
    if isinstance(exp, str) and exp.isdigit():
        exp = int(exp)
    elif isinstance(exp, str):
        print("⚠️ exp não numérico:", exp)
        return True

    if exp > 1e11:
        exp //= 1000

    restante = exp - agora
    horas, minutos = divmod(restante // 60, 60)
    status = "✅ válido" if restante > tolerancia else "⏰ expirado/renovando"
    print(f"UID {payload.get('account_id')} → expira em {horas}h {minutos}m → {status}")

    return restante <= tolerancia

def enviar_token_php(uid, login, token, tipo):
    url = "https://scvirtual.alphi.media/botsistem/sendlike/receber_token.php"
    payload = {"uid": uid, "token": token, "tipo": tipo}
    if login:
        payload["login"] = login
    try:
        r = requests.post(url, data=payload, timeout=5)
        if r.status_code == 200:
            print(f"[{uid}] ✅ Token enviado/atualizado no PHP (tipo {tipo}).")
        else:
            print(f"[{uid}] ⚠️ Erro ao enviar token: {r.status_code}")
    except Exception as e:
        print(f"[{uid}] ❌ Falha ao enviar token: {e}")

def carregar_usuarios_local(arch_file):
    """Carrega usuários de um arquivo local"""
    try:
        with open(arch_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Erro ao carregar arquivo local {arch_file}: {e}")
        return []

# -------------------------------
# Processamento principal
# -------------------------------

def atualizar_tokens(arch_file, token_file, tipo, local=False):
    """Atualiza tokens de um arquivo de usuários e envia para PHP"""
    # Carregar usuários
    if local:
        usuarios = carregar_usuarios_local(arch_file)
    else:
        try:
            url = f"https://raw.githubusercontent.com/minimalsend/likesc/refs/heads/main/{arch_file}"
            usuarios = requests.get(url, timeout=5).json()
        except Exception as e:
            print(f"❌ Erro ao carregar {arch_file}: {e}")
            usuarios = None

    if not usuarios:
        print(f"[{arch_file}] ⚠️ Nenhum usuário carregado")
        return None

    # Criar mapa de tokens existentes por LOGIN
    mapa_tokens = carregar_tokens_existentes(token_file)
    
    print(f"📊 Tokens existentes carregados: {len(mapa_tokens)}")
    if mapa_tokens:
        print(f"📋 Primeiras 5 chaves no mapa: {list(mapa_tokens.keys())[:5]}")

    tokens_validos = []
    novos_tokens = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        for usuario in usuarios:
            uid = usuario.get("uid")
            
            if not uid:
                print(f"⚠️ Usuário sem UID: {usuario}")
                continue

            # Buscar token existente pelo UID
            dado_existente = mapa_tokens.get(str(uid))
            token_atual = dado_existente.get("token") if dado_existente else None
            login_existente = dado_existente.get("login") if dado_existente else uid

            print(f"🔍 Processando: UID={uid}, Token encontrado: {'Sim' if token_atual else 'Não'}")

            # Verifica token existente
            if token_atual:
                print(f"[{uid}] 🔍 Verificando token existente...")
                if token_expirado(token_atual):
                    print(f"[{uid}] ⏰ Token expirado, renovando...")
                    futures[executor.submit(autenticar, usuario)] = (uid, login_existente)
                else:
                    tokens_validos.append({"uid": uid, "token": token_atual, "login": login_existente})
                    print(f"[{uid}] 🔵 Token válido, mantido. Login: {login_existente}")
            else:
                print(f"[{uid}] 🔄 Token ausente, gerando novo...")
                futures[executor.submit(autenticar, usuario)] = (uid, uid)

        # Processa resultados
        for future in as_completed(futures):
            uid, login_existente = futures[future]
            try:
                resultado = future.result()
                if resultado:
                    token = resultado["token"]
                    login_final = login_existente if login_existente != uid else uid
                    novos_tokens.append({"uid": uid, "token": token, "login": login_final})
                    print(f"[{uid}] 🟢 Token renovado/adicionado. Login: {login_final}")
                    enviar_token_php(uid, login_final, token, tipo)
            except Exception as e:
                print(f"[{uid}] ❌ Falha ao gerar token: {e}")

    todos_tokens = tokens_validos + novos_tokens
    random.shuffle(todos_tokens)
    print(f"✅ Total tokens processados (tipo {tipo}): {len(todos_tokens)}")
    return todos_tokens

# -------------------------------
# Rotas Flask
# -------------------------------

@app.route('/')
def index():
    return jsonify({"status": "online", "message": "Token updater service running"})

@app.route('/update-tokens', methods=['POST', 'GET'])
def update_tokens_route():
    try:
        # Verifica se é JSON
        if request.is_json:
            data = request.get_json()
        else:
            # Se não for JSON, tenta pegar os parâmetros do form ou query string
            data = request.form.to_dict() or request.args.to_dict()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        arch_file = data.get('arch_file', 'acc.json')
        token_file = data.get('token_file', 'token_br.json')
        tipo = data.get('tipo', 1)
        local = data.get('local', False)
        
        # Converter para tipos apropriados
        try:
            tipo = int(tipo)
        except (ValueError, TypeError):
            tipo = 1
            
        try:
            local = local.lower() in ('true', '1', 'yes') if isinstance(local, str) else bool(local)
        except:
            local = False
        
        result = atualizar_tokens(arch_file, token_file, tipo, local)
        
        if result:
            return jsonify({
                "status": "success", 
                "tokens_processed": len(result),
                "message": f"Processed {len(result)} tokens successfully"
            })
        else:
            return jsonify({"status": "error", "message": "No tokens processed"}), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})

# -------------------------------
# Thread para execução automática
# -------------------------------

def background_updater():
    """Executa a atualização de tokens em background"""
    ARQUIVOS = [
        {"arch": "acc_brs.json", "token_file": "tokenbr.json", "tipo": 2, "local": False}
    ]
    INTERVALO = 300  # 5 minutos

    while True:
        print("🚀 Iniciando atualização de tokens...")
        for arquivo in ARQUIVOS:
            try:
                atualizar_tokens(
                    arquivo["arch"],
                    arquivo["token_file"],
                    arquivo["tipo"],
                    local=arquivo.get("local", False)
                )
            except Exception as e:
                print(f"❌ Erro geral ao processar {arquivo['arch']}: {e}")
        print(f"⏱ Aguardando {INTERVALO} segundos para próxima execução...\n")
        time.sleep(INTERVALO)

# -------------------------------
# Inicialização
# -------------------------------

if __name__ == "__main__":
    # Inicia a thread de atualização em background
    updater_thread = threading.Thread(target=background_updater, daemon=True)
    updater_thread.start()
    
    # Inicia o servidor Flask
    app.run(host='0.0.0.0', port=5000, debug=False)
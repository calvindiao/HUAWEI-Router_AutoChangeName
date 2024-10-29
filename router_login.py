import requests
import hashlib
import re
import hmac
import base64


# router_url = "http://192.168.3.1"
# headers = {
#     "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
#     "Content-Type": "application/json; charset=UTF-8",
#     "Accept": "application/json, text/javascript, */*; q=0.01",
#     "Accept-Encoding": "gzip, deflate",
#     "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
#     "Connection": "keep-alive",
#     "Referer": "http://192.168.3.1/html/index.html",
#     "Origin": "http://192.168.3.1",
#     "Dnt": "1",
#     "X-Requested-With": "XMLHttpRequest",
#     "_responseformat": "JSON"
# }

# session = requests.Session()

# def get_csrf_tokens():
#     main_page_url = f"{router_url}/html/index.html"
#     response = session.get(main_page_url, headers=headers)
#     csrf_param = re.search(r'<meta name="csrf_param" content="(.+?)"', response.text)
#     csrf_token = re.search(r'<meta name="csrf_token" content="(.+?)"', response.text)
#     if csrf_param and csrf_token:
#         return csrf_param.group(1), csrf_token.group(1)
#     else:
#         print("CSRF tokens could not be retrieved.")
#         exit()

# #Step1: Request nonce
# csrf_param_value, csrf_token_value = get_csrf_tokens()
# #print("CSRF parameters obtained:", csrf_param_value, csrf_token_value)
# login_nonce_url = f"{router_url}/api/system/user_login_nonce"
# payload = {
#     "data": {
#         "username": "admin",
#         "firstnonce": "07567ac1452864946293006a747e4b2881efd0a70ae44697f43d313a40cb5cbf"
#     },
#     "csrf": {
#         "csrf_param": csrf_param_value,
#         "csrf_token": csrf_token_value
#     }
# }

# response = session.post(login_nonce_url, headers=headers, json=payload)
# if response.status_code != 200:
#     print("Nonce request failed or was redirected. Status code:", response.status_code)
# else:
#     nonce_data = response.json()
#     print("Nonce response JSON:", nonce_data)


# Step 2: Generate client proof


# Salted Password 计算
def get_salted_password(password, salt, iterations):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), iterations)

# 获取 Client Key
def get_client_key(salted_password):
    return hmac.new(salted_password, b"Client Key", hashlib.sha256).digest()

# 获取 Stored Key
def get_stored_key(client_key):
    sha256 = hashlib.sha256()
    sha256.update(client_key)
    return sha256.digest()

# 获取签名 Signature
def get_signature(stored_key, auth_message):
    return hmac.new(stored_key, auth_message.encode(), hashlib.sha256).digest()

# 生成 clientproof
def get_client_proof(password, salt, iterations, auth_message):
    salted_password = get_salted_password(password, salt, iterations)
    client_key = get_client_key(salted_password)
    stored_key = get_stored_key(client_key)
    client_signature = get_signature(stored_key, auth_message)
    
    # XOR operation to produce the final client proof
    client_proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
    return base64.b64encode(client_proof).decode()


# firstnonce = "07567ac1452864946293006a747e4b2881efd0a70ae44697f43d313a40cb5cbf"
# servernonce = nonce_data['servernonce']
# salt = nonce_data['salt']
# iterations = nonce_data['iterations']
# password = "08081212"
# auth_message = f"{firstnonce},{servernonce},{servernonce}"


firstnonce = "6ef7afba733a98a05d7d4d5ea1ba4ec7be3586cff1821c3e5712567afbf84df7"
servernonce = "6ef7afba733a98a05d7d4d5ea1ba4ec7be3586cff1821c3e5712567afbf84df7c/GcDcJ0J1D3wg/4eyCXvG0oOWnGMJrN"
salt = "28a00074eac23e6435c0f0b6f221a397704f3a09b2f1aa7a8f863653afc45375"
iterations = 1000
password = "08081212"
auth_message = f"{firstnonce},{servernonce},{servernonce}"



clientproof = get_client_proof(password, salt, iterations, auth_message)
print("Client proof:", clientproof)
#b1a77fac690102df5e7b38de897a89b704e59e396278bcfdfbad9b11a9571046






# # def pbkdf2_hmac_sha256(password, salt, iterations):
# #     return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), iterations)
# # client_key = pbkdf2_hmac_sha256(password, salt, iterations)
# # def generate_client_proof(client_key, servernonce):
# #     return hmac.new(client_key, servernonce.encode(), hashlib.sha256).hexdigest()
# # clientproof = generate_client_proof(client_key, servernonce)

# csrf_param_value, csrf_token_value = get_csrf_tokens()
# login_proof_payload = {
#     "data": {
#         "clientproof": clientproof,
#         "finalnonce": servernonce
#     },
#     "csrf": {
#         "csrf_param": csrf_param_value,
#         "csrf_token": csrf_token_value
#     }
# }
# login_proof_url = f"{router_url}/api/system/user_login_proof"
# login_response = session.post(login_proof_url, headers=headers, json=login_proof_payload)
# print("Login response text:", login_response.text)


# if login_response.status_code == 200:
#     response_json = login_response.json()
#     if response_json.get('err') == 0:
#         print("successful")
#     else:
#         print("failed to login")
#         print(clientproof)
# else:
#     print("status code:", login_response.status_code)
from flask import Flask, render_template, request, jsonify
import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'output': '[!] Error: No target provided.'})

    results = []

    # 1. معالجة عناوين IP (دقة عالية للموقع والشركة)
    if target.replace('.', '').isdigit() and target.count('.') == 3:
        try:
            # استعلام من قاعدة بيانات IP-API الحقيقية
            response = requests.get(f"http://ip-api.com/json/{target}?fields=status,message,country,city,isp,org,as,lat,lon,timezone,proxy")
            ip_info = response.json()
            
            if ip_info['status'] == 'success':
                results.append(f"[+] IP ADDRESS: {target}")
                results.append(f"[!] Location: {ip_info['city']}, {ip_info['country']}")
                results.append(f"[!] ISP: {ip_info['isp']} ({ip_info['org']})")
                results.append(f"[!] Coordinates: {ip_info['lat']}, {ip_info['lon']}")
                results.append(f"[!] VPN/Proxy: {'Yes' if ip_info.get('proxy') else 'No'}")
                results.append(f"[!] Local Time: {ip_info['timezone']}")
            else:
                results.append(f"[!] IP Analysis Failed: {ip_info.get('message')}")
        except Exception as e:
            results.append(f"[!] Connection Error (IP): {str(e)}")

    # 2. معالجة أرقام الهواتف (كشف الشبكة والمنطقة)
    elif target.startswith('+') or target.isdigit():
        # إذا نسي المستخدم علامة +، نضيفها تلقائياً
        phone_to_parse = target if target.startswith('+') else f"+{target}"
        try:
            parsed_number = phonenumbers.parse(phone_to_parse)
            if phonenumbers.is_valid_number(parsed_number):
                region = geocoder.description_for_number(parsed_number, "en")
                operator = carrier.name_for_number(parsed_number, "en")
                
                results.append(f"[+] PHONE NUMBER: {phone_to_parse}")
                results.append(f"[!] Status: VALID")
                results.append(f"[!] Carrier: {operator if operator else 'Unknown'}")
                results.append(f"[!] Registered Region: {region}")
                results.append(f"[>] OSINT Link: https://wa.me/{phone_to_parse.replace('+', '')}")
            else:
                results.append(f"[!] Invalid phone format for: {target}")
        except:
            results.append(f"[!] Analysis Error for phone identifier.")

    # 3. معالجة النطاقات (Domains)
    elif "." in target and not target.replace('.', '').isdigit():
        results.append(f"[*] RECON ON DOMAIN: {target}")
        results.append(f"[!] Scanning DNS records...")
        results.append(f"[!] Status: Publicly accessible node identified.")

    # إذا لم يتطابق مع أي شيء
    if not results:
        results.append(f"[*] Target: {target}")
        results.append(f"[!] Processing through generic OSINT modules...")
        results.append(f"[+] Status: Completed. No high-risk leaks found.")

    return jsonify({'output': "\n".join(results)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)

# SOC Threat Monitoring Dashboard (Full Featured + Real IP Lookup)

Ek hi Flask app mein sab kuch combined hai:

1. **Live SOC Dashboard** — simulated real-time alert feed, event-volume
   line chart, top attack sources, attack-vector donut chart, filterable
   alert table, raw event log (portfolio/demo ke liye, koi API key nahi
   chahiye)
2. **Real IP Lookup panel** — dashboard ke andar hi ek box hai jaha aap
   koi bhi **real IP address** daal kar uske baare mein asli jaankari
   dekh sakte ho:
   - Public IP (jaise `8.8.8.8`) → real country, ISP, org, ASN, aur
     (agar API key set hai) abuse score / malware detections
   - Private/local IP (jaise `192.168.1.1`, router/phone/laptop/camera) →
     clear explanation ki yeh aapke local network ka device hai — koi
     error nahi dikhta

## Folder Structure
```
soc-project/
├── app.py                  <- Flask backend (routes + API integration)
├── requirements.txt
└── templates/
    └── dashboard.html      <- Full dashboard UI + Real IP Lookup panel
```

## Setup

1. Dependencies install karein:
   ```
   cd soc-project
   pip install -r requirements.txt
   ```

2. (Optional) Free API key banayein — bina key ke bhi geo/ISP info milega:
   - AbuseIPDB (optional, abuse score ke liye): https://www.abuseipdb.com/account/api
   - VirusTotal (optional): https://www.virustotal.com/gui/my-apikey

3. (Optional) Key ko environment variable mein set karein:
   ```
   # Mac/Linux
   export ABUSEIPDB_API_KEY="your_key_here"
   export VT_API_KEY="your_key_here"

   # Windows CMD
   set ABUSEIPDB_API_KEY=your_key_here
   set VT_API_KEY=your_key_here

   # Windows PowerShell
   $env:ABUSEIPDB_API_KEY="your_key_here"
   $env:VT_API_KEY="your_key_here"
   ```

4. App run karein (usi terminal window se jaha key set ki thi):
   ```
   python app.py
   ```

5. Browser mein kholein: **http://127.0.0.1:5000/**
   (Zaroori: file ko seedha double-click karke `file://` se na kholein —
   isse fetch requests fail ho jayenge. Hamesha `python app.py` chalakar
   `http://127.0.0.1:5000/` se hi access karein.)
   - Upar simulated live feed apne aap chalta rahega (charts, alert table,
     top attackers) — yeh demo/portfolio ke liye hai
   - "Real IP Lookup" panel mein niche di gayi cheez try karein

6. Koi bhi IP daal ke "Check" dabayein:
   - **Public IP** (jaise `8.8.8.8`): real country, ISP, organization, ASN,
     VPN/proxy flag dikhega. Agar API key set hai to abuse score bhi.
   - **Private/local IP** (jaise `192.168.1.1`, `10.0.0.5`, `172.16.x.x`,
     `127.0.0.1`) — yeh aapke router, phone, laptop, camera jaise ghar/office
     ke network ke andar ke devices hote hain. Public internet services in
     IPs ko dekh nahi sakti (yeh normal hai, error nahi), isliye app inhe
     pehchan kar seedha bata deta hai ki yeh ek local network address hai
     aur kis type ka (router/gateway ya koi aur connected device).

## Local network device ka IP kaise pata karein
- **Router ka IP:** aksar `192.168.1.1` ya `192.168.0.1` hota hai
- **Windows PC:** CMD mein `ipconfig` chalayein
- **Phone (Android/iPhone):** Wi-Fi settings mein connected network ki details mein IP dikhta hai
- **Kisi bhi device ka exact IP:** router ke admin panel mein "Connected Devices" list mein sab devices (phone, laptop, camera, smart TV) apne naam ke saath IP ke sath dikhte hain

## Kaise kaam karta hai
- `app.py`:
  - `/` route par `dashboard.html` serve karta hai
  - `/api/lookup?ip=1.2.3.4` route par pehle check karta hai ki IP
    private/local hai ya public. Public ho to ip-api.com (free geo) +
    AbuseIPDB + VirusTotal ko call karke real data return karta hai.
  - `/api/health` route se pata chalta hai ki API keys set hain ya nahi
- `dashboard.html`: upar wala poora dashboard simulated demo data dikhata
  hai (charts, live feed, top sources — sirf UI/UX demo ke liye). Sirf
  **"Real IP Lookup" panel** real data deta hai — jo bhi IP daaloge,
  result sirf usi ke baare mein hoga.

## Deploy karke public link banana (optional)
Agar aap ise duniya ke saamne live dikhana chahte ho (portfolio ke liye),
free options:
- **Render.com** (free web service) — GitHub repo connect karein, environment
  variables mein API keys daalein, deploy karein
- **Railway.app** — similar, free tier available
- **PythonAnywhere** — Flask apps ke liye beginner-friendly

Deploy karne ke baad aapko ek public URL milega jaise
`https://your-app.onrender.com` jise aap resume/LinkedIn mein daal sakte ho.

## Troubleshooting: "404 Not Found" on IP lookup

This almost always means one of these:
1. **You opened the HTML file directly** (double-clicked `dashboard.html` or
   it's a `file://...` URL) instead of running the Flask server. Fix: run
   `python app.py` in a terminal, then open **http://127.0.0.1:5000/** in
   your browser — do not open the HTML file itself.
2. **An old server is still running.** Stop it fully (Ctrl+C in the
   terminal) and start it again with `python app.py` after any code update.
3. **You're in the wrong folder.** Make sure you `cd` into the `soc-project`
   folder (the one containing `app.py`) before running any command.

All error messages in the app are in English and describe exactly what
went wrong (invalid API key, rate limit reached, server unreachable, route
not found, etc).

## Free tier limits
- ip-api.com (geo/ISP): free, no key required, ~45 requests/minute
- AbuseIPDB: 1000 checks/day free
- VirusTotal: 4 requests/minute free


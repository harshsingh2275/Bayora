# Deployment Guide (cloud VM pe live karna)

Ye guide **T12 / P-11** ke time use hoti hai, yaani jab local stack mein `make check` green ho chuka ho. Deploy ke baad ka rozmarra kaam `docs/operations-guide.md` mein hai.

**Architecture ek line mein:** ek Linux VM, uspe Docker Compose, aur sirf `web` (Caddy) container public hai (ports 80 aur 443). Baaki sab internal networks pe hain. Tenant API (`/v1/*`) public site se kabhi reachable nahi.

---

## Step 0: Pehle ye ready ho

- [ ] Local VM pe `make check` green (break-it table mein sab probes pass)
- [ ] Tag `t11-done` ya usse aage (frontend ready)
- [ ] M-18 (cloud VM) aur M-19 (domain/DNS) complete
- [ ] Model file ka naam aur raw datasets ki files tumhare paas hain

## Step 1: Server tayyar karna

```bash
ssh ubuntu@<SERVER_IP>
sudo apt update && sudo apt -y upgrade
sudo apt -y install git make openssl python3 python3-venv ca-certificates curl
```
Docker ko Docker ki official docs ke "Install Docker Engine on Ubuntu" tareeke se install karo (M-02 jaisa), phir:
```bash
sudo usermod -aG docker $USER   # logout/login karo
docker compose version
```
**Firewall ki do layers rakho:**
1. Provider ka security group/list: 22 (sirf apni IP), 80, 443 allow; baaki sab band.
2. Server pe `ufw` ke bharose mat raho: **Docker published ports ko ufw ke bypass karke khol deta hai.** Isliye compose mein sirf `web` ke ports publish hain, aur provider firewall wahi final guard hai.

**Swap (optional par safe):** chhoti RAM wale VM pe model ke saath out-of-memory se bachne ke liye 2 GB swap add kar sakte ho (verify karo ki tumhare provider/OS pe theek hai).

## Step 2: Code lana

```bash
git clone git@github.com:<tumhara-username>/bayora.git
cd bayora
git checkout <release-tag>      # jaise t13-done ya v1.0
```
Deploy key ya HTTPS token use karna ho toh GitHub docs dekho. Token kahin save mat karo.

## Step 3: Secrets **server pe hi** banao

```bash
./scripts/gen-secrets.sh
ls -la secrets/
```
- Local machine ke secrets server pe copy **mat** karo.
- `cat secrets/admin_token` se admin token nikaal ke apne password manager mein rakho.
- `verifier/trusted_pubkey.pem` is server ki apni public key hai. (Local repo wali alag key hogi; server ki public key ko repo mein commit karna ho toh alag branch/file mein, taaki local key se confuse na ho.)

## Step 4: Model aur data

```bash
mkdir -p data/models data/raw
# model: wahi file jo M-05 mein use ki thi
wget -O data/models/<file-name>.gguf "<hugging-face-resolve-url>"
```
Raw datasets apne laptop/VM se copy karo:
```bash
# apne local machine se:
scp -r data/raw ubuntu@<SERVER_IP>:~/bayora/data/
# phir server pe:
python3 scripts/prepare_datasets.py
ls -lh data/red/pool.jsonl data/blue/bundles/
```

## Step 5: `.env` (production)

```bash
cp .env.example .env
nano .env
```
Zaroori values: `DOMAIN=<tumhara-domain>`, `MODEL_FILE=<file-name>.gguf`, `MODEL_THREADS` (server ke physical cores ke barabar), `MODEL_CTX`, `MODEL_PARALLEL=2`, `DEFAULT_CACHE_MODE=isolated`. Secrets `.env` mein **nahi** jaate.

## Step 6: Chalana

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose ps
```
Pehli baar Caddy ko HTTPS certificate lene mein thoda time lag sakta hai. Logs dekho:
```bash
docker compose logs -f web
```
**ARM server pe:** agar koi image build ya pull fail ho toh `docs/verified-notes.md` aur architecture §15 item 7 dekho (images ka arm64 support).

## Step 7: Verify karo (sab karna hai)

Apne laptop se:
```bash
curl -i https://<DOMAIN>/api/health
curl -i https://<DOMAIN>/v1/red/work        # 404 hona chahiye
nmap -Pn <SERVER_IP>                         # sirf 22 (agar tumhari IP se), 80, 443 khule hon
```
Server pe:
```bash
make breakit          # sab probes pass
./scripts/seed-real-run.sh   # ek baseline aur ek hardened run, real model ke saath
make timing           # dono modes ka timing experiment
make verify-log
```
Browser mein site kholo: Overview, Runs, Audit log (Verify now), Break-it, Timing, Threat model, sab real data dikhaye. Operator login admin token se.

## Step 8: Deploy ke baad turant

1. Log ka **head hash** bahar publish karo (M-21).
2. `./scripts/backup.sh` chalao aur archive laptop pe download karo.
3. Server ka snapshot (provider ki console se) le lo.
4. `docs/operations-guide.md` ka "pre-demo checklist" ek baar chalao.

## Rollback

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml down
git checkout <purana-tag>
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```
Data (log aur DB) named volumes mein hai, `down` se delete nahi hota. **`down -v` kabhi mat chalana**, wo volumes (aur audit log) mita deta hai.

## Troubleshooting

| Problem | Pehle ye dekho |
|---|---|
| HTTPS certificate nahi mil raha | DNS sahi IP pe point kar raha hai? Port 80 aur 443 provider firewall mein khule hain? `docker compose logs web` |
| Site khulti hai par data nahi | `docker compose ps` mein gateway/logger healthy hain? `curl https://<DOMAIN>/api/health` |
| Run atak jaata hai | `docker compose logs red blue gateway`, model slow ho sakta hai: `docker stats`, H-05 prompt |
| Model container restart loop | Memory kam hai (`docker stats`, `dmesg | grep -i oom`), ya model file ka naam `.env` mein galat |
| `make breakit` mein probe fail | Ye bug hai, deploy mat karo; agent ko H-01/H-04 prompt do |
| Disk full | `docker system df`, purani images `docker image prune`; volumes mat chhedna |
| Server reboot ke baad band | Compose ke services `restart: unless-stopped` hain; Docker service enabled hai (`sudo systemctl enable docker`) |

## Security reminders

- Server pe SSH password login band rakho (sirf key).
- Admin token ko kabhi URL, screenshot ya chat mein mat daalo.
- Sirf `web` ke ports publish hone chahiye. `docker ps` mein koi aur `0.0.0.0:` mapping dikhe toh turant rukko.
- Public site read-only hai; mutation sirf admin token se, aur ek time pe ek hi run chalti hai.

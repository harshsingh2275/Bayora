# Manual Actions (jo kaam tumhe khud karna hai, coding nahi)

Har item ka ID **M-xx** hai. `docs/start-to-finish-guide.md` batata hai kab kaunsa karna hai.

**Pehle ek zaroori baat:** is project mein **koi paid API key ya AI API key nahi chahiye**. Model local chalta hai. Sirf ye accounts/tokens lagenge: GitHub, (optional) Hugging Face, cloud VM provider ka account, aur ek free DNS (DuckDNS) ka token. Koi bhi secret kabhi git mein, chat mein ya screenshot mein mat daalna.

Roles: **SH** = Shashwat (Build Lead), **SI** = Siddhartha (Security Auditor), **SN** = Sneha (Narrative and Demo Lead).

---

## Setup (Day 1 subah)

### M-01: Ubuntu VM VirtualBox mein  [SH, ~1h]
1. VirtualBox mein naya VM: Ubuntu 24.04 LTS (Desktop, kyunki Antigravity GUI app hai).
2. Settings: RAM **8 GB** (agar PC mein 16 GB ya zyada hai; kam ho toh 6 GB), CPU **4 cores**, disk **60 GB** (dynamically allocated). Ye mere suggested numbers hain, tumhare PC ke hisaab se adjust karo.
3. Network: NAT. Dashboard Windows browser mein dekhna ho toh port forwarding: Host 8088 → Guest 8088.
4. Ubuntu install karke `sudo apt update && sudo apt -y upgrade`, phir VirtualBox Guest Additions install karo (clipboard aur screen resize ke liye).
5. **Snapshot lo**: "clean-ubuntu".
**Check:** `uname -a` aur `lsb_release -a` chalke Ubuntu dikhe.

### M-02: Docker aur Compose  [SH, ~20 min]
1. Docker ki official docs se "Install Docker Engine on Ubuntu" (apt repository wala tareeka) follow karo. Ubuntu ka purana `docker.io` package mat lo.
2. `sudo usermod -aG docker $USER`, logout/login. (Dhyan: docker group root jaisa power deta hai; sirf is VM mein theek hai.)
**Check:**
```bash
docker --version
docker compose version
docker run --rm hello-world
```
Compose **v2** hona chahiye (`docker compose`, bina hyphen ke).

### M-03: Git aur GitHub repo  [SH, ~15 min]
1. `sudo apt -y install git make openssl python3 python3-venv` (python3 pehle se hoga).
2. GitHub pe naya repo `bayora` banao. Abhi **private** rakho. Submission ke time public karna padega ya nahi, ye M-09 mein check karo.
3. SSH key banao (`ssh-keygen -t ed25519`), public key GitHub mein add karo.
4. `git config --global user.name` aur `user.email` set karo.
**Check:** `ssh -T git@github.com` greeting dikhaye.

### M-04: Antigravity setup  [SH, ~20 min]
1. Antigravity ko **VM ke andar** install karo (Linux version). Mujhe verify nahi ki Linux build tumhare time pe available hai ya nahi; agar nahi hai toh Antigravity Windows pe chalao aur VM se SSH remote connect karne ka tareeka dekho (ye bhi mujhe verify nahi, pehle Antigravity ki docs dekhna).
2. Apne Google account se login karo.
3. Repo folder kholo, aur `AGENTS.md` root mein ho. Agar Antigravity ye file khud nahi padhta toh har naye session ke start mein `docs/agents.md` ka content paste karo (ye mujhe verify nahi hai ki Antigravity AGENTS.md ko automatically padhta hai).
4. Model picker mein dekho kaun se Claude models available hain aur quota kitna hai. `docs/model-guide.md` padho.
**Check:** ek chhota test prompt do ("list files in this repo") aur agent terminal mein command chala paye.

### M-05: Model file download  [SH, ~15 min, P-02 se pehle]
1. Hugging Face pe Qwen2.5-0.5B-Instruct ka GGUF repo kholo (Qwen ke official `Qwen2.5-0.5B-Instruct-GGUF`). **Exact file name aur license page pe khud verify karo**; plan hai `q4_k_m` quantization wali file.
2. Download karke `data/models/` mein rakho (repo ke andar, par ye git mein nahi jaayegi):
```bash
mkdir -p data/models
# browser se download karke rakh do, ya:
# wget -O data/models/<file-name>.gguf "<hugging-face-resolve-url>"
```
3. `.env` mein `MODEL_FILE=<file-name>.gguf` likho (P-01 ke baad `.env.example` se copy karke `.env` banega).
**Check:** `ls -lh data/models/` mein file dikhe (0.5B Q4 ke liye lagbhag kuch sau MB; exact size verify karo).

### M-06: Datasets ki raw files  [SI ya SN, ~20 min, P-06 se pehle]
1. **AdvBench:** `llm-attacks` GitHub repo se `harmful_behaviors.csv` (data/advbench folder mein) download karo. Exact path repo mein verify karo.
2. **Gandalf ignore-instructions:** Hugging Face pe `Lakera/gandalf_ignore_instructions` dataset page se download/export karo. Agar access terms accept karne padein toh karo.
3. Dono ko `data/raw/` mein rakho. Ye files git mein nahi jaayengi.
4. In datasets mein harmful ya offensive text hota hai. Sirf local research ke liye use karo, kahin post mat karo, slides mein sirf counts dikhao.
**Check:** `ls data/raw/` mein dono files.

### M-07: Secrets generate karna  [SH, P-01 ke turant baad]
```bash
./scripts/gen-secrets.sh
ls -la secrets/
```
- Secrets ki values kisi se share mat karo (WhatsApp, chat, screenshot, agent chat sab mana).
- `admin_token` ki value **ek password manager ya apni private notes mein** rakho; dashboard ke operator login mein wahi chahiye hoga. File se padhne ke liye: `cat secrets/admin_token` (sirf apne terminal mein).
- `verifier/trusted_pubkey.pem` public key hai, isko commit kar sakte ho.
**Check:** `git status` mein `secrets/` na dikhe.

### M-08: Docs repo mein copy karna  [SH, ~5 min]
1. Saari md files `docs/` folder mein rakho.
2. `design.md` jab Claude se ban jaaye, wo bhi `docs/design.md` mein (Day 2 ki shaam tak chahiye; warna fallback UI chalegi).
3. `cp docs/agents.md AGENTS.md` ya `make sync-agents`.

### M-09: Hackathon ke rules check karna  [SN, ~30 min, Day 1]
Organizers ki site/Discord/email se confirm karo:
- Submission format kya hai (repo link, demo video, live link, PPT)?
- Deadline kitne baje, aur team ko kaunsi platform pe submit karna hai?
- AI coding tools allowed hain ya koi disclosure chahiye?
- Repo public hona chahiye ya private chalega?
- Live demo ka format kya hoga (judges ke saamne ya recorded)?
Jawab `docs/hackathon-rules-notes.md` mein likh do (ye sirf tumhare liye hai).

### M-10: Daily safety habit  [SH, har task ke baad]
- Har task ke baad `git push` aur tag push: `git push && git push --tags`.
- Har din ke end mein VirtualBox **snapshot** lo ("day1-end", "day2-end", ...).
- Model/secrets ke bina bhi repo ko dobara clone karke chalana possible hona chahiye.

---

## Auditor checkpoints (SI ka asli kaam)

Auditor ka rule: **jo ye padhe wo build na kare**. Har checkpoint pe agent ke `S-xx` prompt ko ek **naye session** mein chalao (S-prompts `docs/prompt.md` mein), aur neeche wali cheezein khud bhi dekho.

### M-11: Checkpoint 1, T01 ke baad  [SI, ~45 min]
Padhne ki files: `docker-compose.yml`, saare `Dockerfile`, `.gitignore`.
Dhoondo:
- Kisi service mein `privileged`, `network_mode: host`, `pid: host`, `devices`, ya `docker.sock` hai? **Nahi hona chahiye.**
- Har custom service mein `user`, `cap_drop: [ALL]`, `no-new-privileges`, `read_only`, `mem_limit`, `cpus`, `pids_limit` hai?
- Networks `internal: true` hain (front-net ke alawa)?
- `red` sirf `red-net` pe hai, `blue` sirf `blue-net` pe? Sirf `gateway` multiple networks pe?
Manual test:
```bash
docker compose exec red sh -c 'getent hosts blue model logger verifier; echo exit=$?'
docker compose exec red sh -c 'id; grep -E "CapEff|NoNewPrivs|Seccomp" /proc/self/status'
docker compose exec red sh -c 'touch /testfile; echo write_exit=$?'
curl -i http://localhost:8088/v1/red/work
```
Expected: hostnames resolve nahi hote, uid 10001, CapEff sab zero, NoNewPrivs 1, Seccomp 2, write fail, curl 404.

### M-12: Checkpoint 2, T03 ke baad  [SI, ~45 min]
Padhne ki files: gateway ki auth wali file, request models wali file, model client wali file.
Dhoondo: token comparison `compare_digest` se hai? Request models mein `extra="forbid"`? Model ko jaane wali request kisi client field se bani to nahi? Response se `timings`/`usage` hata hai? Logs mein token chhapta to nahi?
Manual test (galat token ke saath, red container ke andar se):
```bash
curl -i http://localhost:8088/api/health
docker compose exec red python -c "import urllib.request as u; r=u.Request('http://gateway:8000/v1/blue/work',headers={'Authorization':'Bearer wrong'}); print(u.urlopen(r).status)"
```
Dusri command mein HTTP error aana chahiye (401 ya 403), `200` nahi.

### M-13: Checkpoint 3, T04 ke baad  [SI, ~45 min]
Padhne ki files: logger ka hash-chain code, verifier ka main code.
Dhoondo: verifier logger ka code import to nahi karta? Verifier ka log volume read-only mount hai? Private key sirf logger mein hai?
Manual test: site/API se `GET /api/verify` chalao, phir tamper demo (`/api/verify/tamper-demo`). **Real log file ko haath mat lagana**; demo in-memory copy pe chalta hai.
Dhyan: "truncate after last checkpoint = not detectable" ek **expected limitation** hai, bug nahi.

### M-14: Checkpoint 4, T05 aur T06 ke baad  [SI, ~1h]
Padhne ki files: run lifecycle wala code, defense bundle validation, results/reports wale endpoints.
Dhoondo: mid-run kisi bhi response/log mein prompt text ya outcome to nahi? Blue ka report conclusion se pehle 403? Digest mismatch pe 409? Regex pe timeout laga hai?
Manual test: run chalao aur beech mein public `/api/runs/<id>` aur `/api/log` dekho. Sirf digests dikhne chahiye.

### M-15: Khud todne ki koshish  [SI, ~30 min]
Red container ke andar se ye sab try karo, sab fail hona chahiye (slim images mein wget/curl nahi hota, isliye python use kiya hai):
```bash
docker compose exec red python -c "import urllib.request as u; print(u.urlopen('http://model:8080/health', timeout=2).status)"   # fail hona chahiye
docker compose exec red python -c "import urllib.request as u; print(u.urlopen('http://1.1.1.1', timeout=2).status)"            # fail hona chahiye
docker compose exec red sh -c 'ls /data /run/secrets'                                                                           # sirf apni cheezein
docker compose exec red sh -c 'cat /run/secrets/blue_token'                                                                     # exist nahi karna chahiye
```
Aur blue container se same. Jo cheez pass ho gayi (yaani todna possible hua), wo **bug hai**: agent ko H-prompt se fix karwao.

### M-16: Timing results review  [SI + SH, ~45 min, T08 ke baad]
- Dashboard ke Timing view mein dono modes dekho: `shared` mein HIT medians MISS se kam hain? `isolated` mein fark gayab hai?
- Report ka verdict **jaisa hai waisa** rakho. Number tune mat karwana. Agar `shared` mein signal nahi mila toh bhi honestly likho (aur H-05/P-08 ke notes dekho).
- `S-05` prompt ek naye session mein chalao.

### M-17: Break-it report review  [SI, ~30 min, T09 ke baad]
- `make breakit` ka table padho. Har probe ka matlab samjho (architecture §10). Judges isi table pe sawal puchenge.
- Negative demo chalao: `scripts/breakit-negative-demo.sh`, aur dekho ki control hatane pe probe fail hota hai.

---

## Deployment (Day 4)

### M-18: Cloud VM  [SH, ~45 min]
1. Ek Linux VM chahiye (Ubuntu 24.04 LTS). Options: Oracle Cloud ka free tier (ARM instances kabhi capacity ke wajah se milte nahi, aur card verification lagta hai), ya koi chhota paid VPS (DigitalOcean, Hetzner, AWS EC2 jaise). **Prices aur free-tier ki current availability mujhe verified nahi hai**; khud check karo.
2. Kam se kam **2 vCPU aur 4 GB RAM** soch ke chalo, phir model ka real memory use measure karke decide karo (ye mera estimate hai, verified nahi).
3. SSH key add karo. Firewall (provider ke security group/list mein): 22 (sirf apni IP se), 80, 443.
4. Agar ARM instance liya toh `docs/verified-notes.md` mein check karo ki images arm64 ke liye hain.
**Check:** `ssh ubuntu@<ip>` chalta hai.

### M-19: Domain / HTTPS ke liye DNS  [SH, ~15 min]
- Free: DuckDNS (duckdns.org) pe subdomain banao aur uska IP cloud VM ka IP set karo (token DuckDNS dashboard se; token kahin share mat karo).
- Ya apna koi domain ho toh A record set karo.
- Caddy ko HTTPS certificate tabhi milega jab DNS sahi IP pe point kar raha ho aur port 80/443 khule hon.
**Check:** `nslookup <tumhara-domain>` VM ka IP dikhaye.

### M-20: Deploy steps  [SH]
`docs/deployment-guide.md` ke steps line-by-line follow karo.

### M-21: Log ka head hash bahar publish karna  [SH, ~10 min]
Deployed system pe run + verify ke baad dashboard se `head hash` copy karo aur kahin bahar rakho jahan tum ise baad mein badal nahi sakte (jaise GitHub release notes ya ek public gist, aur LinkedIn/X post mein bhi daal sakte ho). Isse "tail truncation" wali limitation ka practical jawab milta hai. Detail: `docs/operations-guide.md`.

---

## Submission aur presentation (Day 4)

### M-22: Evidence, screenshots, video  [SN, ~2h]
- Screenshots: break-it table (sab pass), timing charts (shared vs isolated), audit log verify OK, tamper demo (detected + honest limitation), run results (baseline vs hardened ASR).
- Demo video (OBS ya Windows Game Bar): `docs/demo-script.md` ke hisaab se, 5 minute se kam. Ek baar poora rehearse karo; ek fallback video bhi rakho agar live demo fail ho.
- PPT mein add karo: **Tech Stack**, **Threat Model and Limitations**, **Results** slides, aur Market slide se "further research" wala node hatao.
- Slides mein sirf wahi claim rakho jo live dikha sako.

### M-23: Final submission  [SN + SH]
- Repo ka README dekho, secrets ya `data/` kuch commit to nahi hua (`git log --stat` skim).
- Repo public karna ho toh karo (M-09 ke jawab ke hisaab se).
- Submission form: repo link, live link, video, PPT. Deadline se kam se kam 1 ghanta pehle submit karo.
- Fresh clone pe `make check` chalake dekh lo (agent ke P-13 ke baad).

### M-24: Team coordination  [teeno]
- Din ke start mein 10 min standup: kal kya hua, aaj kaunsa task, blocker kya hai.
- Din ke end mein: tag push, snapshot, S-prompt results ki list.
- SH agent chalata hai, SI audit karta hai, SN docs/demo/slides sambhalta hai. SN ko Day 2 mein SI se 30 min ka "isolation kya hai" explain session lena hai taaki wo judges ko samjha sake.

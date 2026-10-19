# Operations Guide (deploy ke baad ka kaam)

Ye guide tab use hoti hai jab site live ho chuki ho. Deploy ke steps `docs/deployment-guide.md` mein hain.

Commands server pe project folder (`~/bayora`) se chalte hain. Prod compose ke liye short form:
```bash
alias dcp='docker compose -f docker-compose.yml -f docker-compose.prod.yml'
```

## 1. Roz ka status check (2 min)

```bash
dcp ps                                   # sab healthy?
curl -s https://<DOMAIN>/api/health      # gateway, model, logger, verifier
make verify-log                          # log ok?
docker stats --no-stream                 # CPU/RAM
df -h /                                  # disk
```

## 2. Nayi evaluation run chalana

Site pe operator login (admin token) → Runs → Create run (name, attack count, seed, bundle `baseline` ya `hardened`). Ek time pe ek hi run chalti hai. Run apne aap red aur blue agents se chalegi aur conclude hogi.
Kam attacks (jaise 20-30) se shuru karo, kyunki model CPU pe chal raha hai.

## 3. Cache mode badalna

Operator login → Timing view → toggle `isolated` / `shared`. **Normal state `isolated` hai.** `shared` sirf experiment ke liye hai, aur experiment ke baad wapas `isolated` karna mat bhoolna. Ye badlav audit log mein `cache_mode_changed` ke naam se dikhta hai.

## 4. Timing experiment dobara chalana

```bash
make timing
```
Ye dono modes chalata hai aur report gateway ko post karta hai. Baaki workload (runs) ke dauran mat chalao, warna latency noisy hogi aur numbers kharab honge.

## 5. Break-it dobara chalana

```bash
make breakit
```
Har deploy ya config badlav ke baad chalana. Ek bhi probe fail ho toh wo bug hai, site ko demo ke liye mat chhodo jab tak fix na ho.

## 6. Audit log ka head hash bahar anchor karna

Hash chain akele "tail truncation" (aakhri entries kaat dena) pakad nahi sakti. Iska practical jawab: head hash ko bahar publish karna.
1. Dashboard ke Audit log view se `head` (seq aur hash) copy karo.
2. Kisi aisi jagah save karo jahan baad mein badalna mushkil ho: GitHub release notes ya public gist, aur chaho toh post mein.
3. Baad mein verify karte waqt dekho ki log mein us `seq` pe wahi hash hai.
Ye har bade milestone ke baad karo (deploy ke baad, demo se pehle, submission se pehle).

## 7. Backup

```bash
./scripts/backup.sh
```
Archive aur checksum laptop pe download karo (`scp`). Log aur gateway DB named volumes mein hain. **`docker compose down -v` kabhi mat chalana**, wo volumes mita deta hai.

## 8. Update karna (naya code)

```bash
git fetch --tags && git checkout <naya-tag>
dcp up -d --build
make breakit && make verify-log
```
Naya tag lene se pehle backup lo. Naye feature demo ke 3 ghante pehle freeze karo.

## 9. Secrets rotate karna

Agar kisi token ke leak ka shak ho:
1. `./scripts/gen-secrets.sh --force`
2. `dcp up -d --force-recreate`
3. Naya admin token password manager mein rakho.
**Dhyan:** signing key badalne se purane checkpoints naye public key se verify nahi honge. Isliye key tabhi rotate karo jab zaroori ho, aur purani public key aur uske checkpoints ka record rakho (verifier ke notes mein likho). Demo ke din aisa mat karo.

## 10. Kuch galat ho jaye toh

| Dikkat | Kya karein |
|---|---|
| Site down | `dcp ps`, `dcp logs --tail=100 web gateway`, H-01 prompt |
| Run atak gayi | 10 minute baad auto-abort hoti hai; operator abort bhi kar sakta hai; `dcp logs red blue gateway` |
| Verify fail (`ok: false`) | **Pehle kuch delete/edit mat karo.** Errors list copy karo, backup lo, `seq` dekho; ye ya toh asli tampering hai ya bug. Agent ko H-04 prompt do |
| Model OOM | `docker stats`, `MODEL_CTX` ya threads kam karo, chhota quantization |
| Disk full | `docker system df`, `docker image prune`, purane backups hatao (volumes mat chhedna) |
| Admin token kho gaya | Naya banao (section 9), purana sab invalid ho jaata hai |

## 11. Demo se pehle checklist (30 min pehle)

- [ ] `dcp ps` sab healthy, site HTTPS pe khul rahi hai
- [ ] `make breakit` sab pass
- [ ] `make verify-log` ok, aur head hash anchor kiya hua hai
- [ ] Cache mode `isolated`
- [ ] Ek taaza `baseline` aur ek `hardened` run conclude hui hai (dashboard pe dikh rahi)
- [ ] Timing report dono modes ke liye maujood
- [ ] Operator token tumhare paas hai (screen pe kabhi dikhana nahi)
- [ ] Offline fallback: demo video aur screenshots laptop pe ready
- [ ] Browser tab mein sirf zaroori cheezein khuli, notifications band

## 12. Event ke baad

- Final backup aur head hash anchor.
- Agar top 10 mein aaye aur Manali jaana ho toh live demo ke liye server ko chalu rakho; nahi toh cloud ka kharcha rokne ke liye VM ko stop karo (pehle backup).
- Repo ko tag `v1.0` pe freeze rakho, aur README mein "known limitations" section dobara padho.

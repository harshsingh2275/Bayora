# Bayora: Project ki poori jaankari (Hinglish)

Is file se tum kisi ko bhi (judge, dost, mentor) project samjha sakte ho. Antigravity bhi ise context ke liye padh sakta hai; technical sach `docs/architecture.md` mein hai, aur wahi final hai.

---

## 1. Ek line mein

**Bayora ek aisa platform hai jahan AI ko todne wali team (red), bachane wali team (blue) aur test hone wala AI model (client LLM) ek hi jagah ek saath chalte hain, bina ek doosre ki secret cheezein dekhe, aur har cheez ka ek aisa record bante hai jisme chhed-chhaad pakdi ja sakti hai.**

Project ka naam: Bayora | Team: Coders Club | Hackathon: Hack in Hills '26 | Problem: "Securing Adversarial AI Safety Testing Infrastructure"

## 2. Problem kya hai (aasaan bhasha mein)

AI model ko deploy karne se pehle safety test hota hai: red team usse galat jawab dilwane ki koshish karti hai (jailbreak, prompt injection), blue team defense banati hai. Agar ye sab ek hi shared jagah chal raha ho aur koi bhi doosre ko dekh/samajh sake toh:

- blue team ko attacks pehle se dikh gaye toh wo sirf unhi ke liye defense banayegi (overfit)
- red team ko defense ki logic samajh aa gayi toh wo uske hisaab se attack tune kar legi
- model ke andar ek test ki yaad doosre test mein chali gayi toh result galat

Natija: **result confident dikhta hai par galat hota hai**, aur ek unsafe model "safe" maan ke deploy ho sakta hai. Isliye test karne wala environment khud secure hona chahiye. Bayora wahi environment hai.

**Analogy:** socho do students aur ek examiner ek hi kamre mein exam de rahe hain, aur ek student doosre ki copy dekh sakta hai. Bayora kamre mein deewarein banata hai, ek hi khidki (gateway) rakhta hai jisse sab guzarte hain, aur har cheez ek aisi register mein likhta hai jisme page phaadna ya badalna pakda jaye.

## 3. Hamara solution, step by step

**Teen alag dabbe (containers):** Red, Blue aur Model, har ek apne alag network mein. Ye ek doosre ko seedha dekh ya chhu nahi sakte.

**Ek hi gateway:** teeno ke beech ek hi darwaza hai. Red ya blue model ko seedha nahi bula sakte; sab gateway se guzarta hai. Gateway pehchanta hai ki kaun hai (token), kya kar sakta hai (role), aur kya bhejna allowed hai (whitelist).

**Commit-reveal (pehle wada, baad mein khulasa):** run shuru hone se pehle red apne attacks ka "digest" (ek fingerprint) record karwata hai, blue apni defense ka digest. Run ke dauran koi kisi ki cheez nahi dekh sakta. Run khatam hone ke baad sab khulta hai, aur fingerprint match karke pata chalta hai ki kisi ne beech mein kuch badla nahi.

**Defense = data, code nahi:** blue apni defense rules ki JSON file ke roop mein deta hai. Gateway use apply karta hai. Red ko rules dikhte nahi, blue ko attacks nahi dikhte (jab tak run khatam na ho).

**LLM-specific leak ka test:** AI servers speed ke liye purane prompts ka cache (yaad) reuse karte hain. Agar do tenants ye cache share karein toh ek, doosre ke prompt ko response ki **speed naap ke** guess kar sakta hai (jitna jaldi jawab, utna zyada prefix match). Hum ye leak **naapte hain** (shared mode), phir har tenant ko alag slot dekar rokte hain (isolated mode), aur phir se naapte hain. Numbers jaise aate hain waise hi dikhaate hain.

**Tamper-evident log:** har event pichle event ke hash se jura hota hai (hash chain), aur beech beech mein digital signature wale checkpoints hain. Ek alag verifier program poore log ko check karta hai. Ek bhi entry badli, hatayi ya ulti-seedhi hui toh pakdi jaati hai.

**Break-it runner:** ek program jo khud isolation todne ki koshish karta hai (doosre container tak pahunchna, secrets padhna, internet jaana, galat token se chalna). Har koshish ka pass/fail table banta hai. Jo cheez fail honi chahiye wo agar pass ho jaye toh bug pakda jata hai.

**Threat model:** ek chhota, imaandaar document ki kya protect hota hai aur kya **nahi**.

## 3b. Flow ek example mein

1. Operator site pe "Create run" dabata hai (jaise 50 attacks, bundle: hardened).
2. Red apne private attack pool se 50 prompts chunta hai, unke digests gateway ko commit karta hai.
3. Blue apni defense rules gateway ko deta hai, uska digest commit hota hai.
4. Dono commitments audit log mein likhe jaate hain. Run shuru.
5. Red ek-ek prompt gateway ko bhejta hai. Gateway check karta hai ki ye wahi prompt hai jo commit hua tha, blue ke input rules lagata hai, model ko bhejta hai, output rules lagata hai, aur heuristic se score karta hai.
6. Log mein sirf digests jaate hain, prompt ka text nahi.
7. Red "done" bolta hai. Run conclude hoti hai, results khulte hain, aur results ka digest log mein likha jata hai.
8. Koi bhi verifier chala ke dekh sakta hai ki log asli hai aur results mein chhed-chhaad nahi hui.

## 4. Features ki list

- Alag, locked-down containers (non-root, no capabilities, read-only filesystem, resource limits)
- Network segmentation (internal networks, gateway hi akela pul)
- Token auth + role checks + strict request whitelisting
- Commit-reveal evaluation runs aur sealed results
- Autonomous red aur blue agents
- Defense bundles (rules as data) aur heuristic scoring (ASR)
- Prefix-cache timing leak: shared mode vs isolated mode, statistics ke saath
- Hash-chained signed audit log + independent verifier + tamper demo
- Break-it runner (real attacks) + configuration audit + negative demo
- Public HTTPS dashboard (read-only) + operator controls (admin token)
- Honest threat model

## 5. Tech stack (seedhi bhasha mein)

- **Python + FastAPI**: gateway, logger, verifier, agents
- **Docker Compose**: sab services aur networks
- **llama.cpp server + chhota open model (~0.5B, CPU pe)**: client LLM
- **SQLite**: gateway ka data
- **Ed25519 signatures + SHA-256**: log ki integrity
- **React + TypeScript + Vite**: dashboard; **Caddy**: web server aur HTTPS
- **Antigravity (AI coding agent)**: saara code; **team**: audit, security tests, demo, docs

## 6. Alag kya hai

- Hum **platform ko hi secure** kar rahe hain, sirf model ko test nahi.
- Container isolation se aage jaake **LLM-specific timing leak** ko naapte aur mitigate karte hain.
- Har claim ke peeche **test ya measurement** hai: break-it table, verifier, timing report.
- Hum **limitations khud batate hain** (neeche section 8), isliye claims par bharosa banta hai.

## 7. Users aur business angle

(Market ka koi number hamare paas verified nahi hai, isliye slides ya bolne mein koi figure mat bolo.)
- AI safety teams jinhe compliance ke liye reproducible, verifiable evidence chahiye
- Independent auditors jo bina platform pe bharosa kiye finding verify karna chahte hain
- Wo companies jo LLM apps deploy karti hain aur red-team evaluations karwati hain
- Possible revenue: subscription, enterprise (private deployment), audit reports, custom integrations (ye ideas hain, validated demand nahi)

## 8. Limitations (imaandaari se, judge poochenge)

1. **Kernel shared hai.** Sab containers ek hi Linux kernel pe hain (dev mein wo kernel VirtualBox VM ke andar). Kernel escape se isolation tut sakta hai. Aage ka kaam: gVisor ya microVM.
2. **Gateway aur logger par bharosa karna padta hai.** Inke compromise hone par guarantees tutti hain.
3. **Black-box inference:** red blocked vs allowed dekh ke defense ka *behavior* guess kar sakta hai; rules nahi.
4. **Shared CPU timing:** ek tenant ka load doosre ki latency badha sakta hai. Ye channel mitigate nahi kiya.
5. **Log ka tail truncation:** aakhri checkpoint ke baad ki entries kaatna chain akeli pakad nahi sakti. Hum head hash bahar publish karte hain aur ye limitation dikhate hain.
6. **Scoring heuristic hai** aur model chhota hai. ASR ke numbers rough hain, research-grade nahi.

## 9. Future scope

Hardened runtimes (gVisor/microVMs), aur side channels ka coverage, multi-model support, scale-out multi-host, aur third-party verifiable evidence ko aur strong banana.

## 10. Team

- **Shashwat Singh**: Build Lead (agent chalana, repo, deployment)
- **Siddhartha Singh**: Security Auditor (verification, break-it, tamper tests)
- **Sneha**: Narrative and Demo Lead (slides, threat model language, demo)

## 11. Pitch

**30 second:** "AI safety test tab tak bharosemand nahi jab tak test ka environment secure na ho. Red team, blue team aur model ek shared sandbox mein ek doosre ki cheezein dekh ya samajh sakte hain, aur result galat ho jata hai. Bayora teeno ko alag dabbon mein rakhta hai, ek hi gateway se jodta hai, commit-reveal se wada lock karta hai, aur har event ko aise log mein likhta hai jisme chhed-chhaad pakdi jaati hai. Hum ye sirf kehte nahi, apna break-it runner live isolation todne ki koshish karke dikhata hai."

**2 minute:** upar ka 30 second + (1) commit-reveal ka ek example, (2) timing leak ka graph (shared vs isolated), (3) tamper demo, (4) break-it table, (5) "aur ye cheezein hum protect **nahi** karte" wali limitations slide.

## 12. Judge ke possible sawal aur jawab

1. **"AI ne code banaya, tumne kya kiya?"** Hamari team ne architecture decide kiya, har security-relevant file khud audit ki, aur tests ek alag AI session mein sirf spec se likhwaye taaki agent apna kaam khud grade na kare. Hum har layer ka reason samjha sakte hain.
2. **"Docker containers secure nahi hote."** Sahi, kernel shared hai. Isliye threat model mein ye limitation likhi hai aur gVisor/microVM roadmap mein hai. Hamara claim "containers perfectly secure" nahi, balki "ye boundaries kaam karti hain aur hum unhe tod ke test karte hain".
3. **"Timing leak sach mein measure kiya?"** Haan, pre-registered rule se (p < 0.01 aur AUC > 0.8), dono modes mein, raw samples ke saath. Limitations bhi report mein hain.
4. **"Agar shared mode mein leak na dikhe?"** Tab hum wahi report karte; rule data dekhne ke baad nahi badalte.
5. **"Log ko delete kar do toh?"** Beech ya shuru ki entries hatane par chain/checkpoint tut jate hain. Aakhri checkpoint ke baad ki truncation chain akeli pakad nahi sakti, isliye head hash bahar publish karte hain.
6. **"Blue ke rules red ko leak kyun nahi hote?"** Rules gateway mein data ke roop mein rehte hain, red ko API se sirf response milta hai (blocked ya model ka text); rule ids ya bundle sirf blue ko, aur sirf run ke baad.
7. **"Red blocked/allowed se defense seekh sakta hai."** Haan, ye black-box inference hai, hum ise protect nahi karte aur likhte hain.
8. **"Real products se kaise alag?"** Hum ek reference implementation hain jo isolation, evidence aur honesty pe focus karti hai; market ka koi comparison number hamare paas nahi.
9. **"Scale kaise karoge?"** Abhi single host. Future: multi-host aur per-tenant model instances.
10. **"Scoring bharosemand hai?"** Heuristic hai aur isi tarah label hai; ye platform ka core nahi, core isolation aur evidence hai.

## 13. Chhota glossary

- **Tenant:** ek party (red, blue, ya model) jiska apna alag dabba hai.
- **Gateway:** wo akela darwaza jisse sab guzarte hain.
- **Digest/hash:** kisi data ka fingerprint (SHA-256). Data badla toh fingerprint badal jata hai.
- **Hash chain:** har entry mein pichli entry ka hash, toh beech mein badlaav pakda jata hai.
- **Checkpoint:** chain ke ek point pe digital signature.
- **Side channel:** wo raasta jisse secret seedha nahi, par kisi side effect (jaise response time) se pata chal jata hai.
- **Prefix cache:** model ka purane prompt ke shuruaati hisse ko yaad rakhna taaki jaldi jawab de.
- **ASR:** Attack Success Rate, kitne attacks "kamyab" hue (yahan heuristic).
- **TCB:** wo hissa jispe bharosa karna padta hai (gateway, logger, host).

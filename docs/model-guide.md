# Model Guide: kaunsa task kis model se

Antigravity mein tumhe Claude model aur dusre models (jaise Gemini) mil sakte hain. Mujhe tumhara current quota, rate limits aur exact model names verified nahi pata, isliye neeche "Claude model" ka matlab hai **Antigravity ke model picker mein jo sabse strong Claude model available ho**. Ye meri salah hai, koi measured benchmark nahi.

**Kyun alag-alag?** Is project mein sabse bada risk "kod dikhta hai sahi par security mein chhed hai" wala hai. Jahan ek chhoti galti poore claim ko tod sakti hai, wahan strongest Claude model lo. Jahan galti aasani se dikh jaati hai (UI, docs), wahan default model theek hai.

---

## Tier A: Claude model, zaroori (sabse important ya mushkil)

| Task | Prompt | Kyun mushkil/important hai |
|---|---|---|
| **T03** Gateway core | **P-03** | Auth, role checks, request whitelist, model ko jaane wali request ka control. Yahan ki galti poore isolation ko tod deti hai. |
| **T04** Logger + verifier | **P-04** | Hash chain, canonical JSON, signatures, fail-closed. Chhoti si galti se verification jhooti ho sakti hai. |
| **T05** Run lifecycle (commit-reveal) | **P-05** | Sabse complex logic: states, digest checks, sealed data, regex timeout, results digest. |
| **T08** Timing experiment | **P-08** | Llama.cpp ke asli behavior se jhoojna, statistics sahi karna, honest reporting. |
| **T09** Break-it runner | **P-09** | Real attacks, host aur container dono taraf se, negative demo. |
| **Saare S prompts** | **S-02, S-03, S-04, S-05, S-06** | Adversary ban ke bug dhoondna sabse zyada reasoning maangta hai. S-01 chhota hai (Tier B). |
| **Debugging (security wale)** | **H-02, H-04** | "Test jhootha to nahi?" aur regression ka root cause. |

## Tier B: Claude agar quota bacha hai, warna default model + extra audit

| Task | Prompt | Note |
|---|---|---|
| **T00 + T01** Bootstrap + compose hardening | **P-01** | Config security-critical hai par **S-01** aur **M-11** isko pakad lete hain. |
| **T06** Datasets + agents + bundles | **P-06** | Zyada plumbing hai. Defense bundles ki quality (rules) dhyan se dekho. |
| **T07** Public API | **P-07** | Mid-run sealed-data leak yahan ho sakta hai: S-04 aur M-14 se verify karo. |
| **T12** Deployment | **P-11** | Ports aur firewall ka dhyan. Manual steps ko deployment guide se match karo. |
| **S-01** | S-01 | Checklist wala review. |
| **Dusre debugging prompts** | **H-01, H-03, H-05** | Default model se pehle try karo, na chale toh Claude. |

## Tier C: Default (tez) model theek

| Task | Prompt | Note |
|---|---|---|
| **T02** Model service | **P-02** | Verified flags `docs/verified-notes.md` mein likhwana mat bhoolna; agent se command output maango. |
| **T11** Frontend | **P-10** | Real API ke saath har view khud khol ke check karo. Output kharab lage toh model badal ke ek baar fir try karo. |
| **T13** Docs | **P-12** | Claims ka cross-check M-23 aur threat model se. |
| **T14** Final verification | **P-13** | Sirf bug fix; agar koi serious bug nikle toh Claude se (H-04). |
| **X prompts (stretch)** | **X-01, X-02** | X-01 sirf tab jab sab green; X-02 sirf agar slot pinning kaam na kare. |

---

## Rules of thumb

1. **Ek task = ek naya session = ek hi model.** Beech mein model mat badlo.
2. **Planning ya "thinking" mode** (agar Antigravity mein hai) Tier A tasks ke liye on rakho. Naam aur setting ka exact label mujhe verify nahi, settings mein dekho.
3. **S-prompts hamesha naye session mein.** Jo session build kar chuka hai, wo apna test khud mat likhe.
4. **Implementation aur audit alag model se bhi karwa sakte ho.** Jaise build Gemini se, S-prompt Claude se (ya ulta). Alag model alag galtiyan pakadta hai.
5. **Agent ke "done" par bharosa mat karo.** Report ka EVIDENCE section dekho aur M-checkpoints chalao.

## Quota kam ho toh (priority order)

Claude ka quota jo bacha hai, use is order mein kharch karo:
1. **S-04** (commit-reveal attacks) aur **S-02** (gateway authz), kyunki yahan leaks sabse costly hain
2. **P-05**, **P-04**, **P-03** (implementation ke teen sabse sensitive hisse)
3. **P-08**, **P-09** (timing aur break-it)
4. **S-03**, **S-05**, **S-06**
5. Baaki sab default model se

Agar Claude ka quota mid-task khatam ho jaye:
- Task ko chhoda mat raho beech mein; Gemini se ek chhoti bug-fix pass chalao (**H-03** se scope lock karke), phir quota wapas aane par us task ke liye **H-02** (test-the-tests) Claude se.
- Quota reset ka time mujhe nahi pata; Antigravity ke usage page pe dekho.
- Jo task Tier A ka tha aur default model se hua, uska S-prompt **zaroor** chalao, bhale wo baad mein ho.

## Frontend aur design

`docs/design.md` jab ban jaaye, P-10 ke liye wahi reference hai. Agar frontend ka kaam parallel chalana hai toh uska session alag ho (backend session se mixed nahi), aur API contract `docs/architecture.md` §5 aur `/api/openapi.json` se aaye.

# Start to Finish Guide

Is file mein sirf ye hai: **kya karna hai, kis order mein, aur kaunsi file dekhni hai.** Har step ki details uske saamne likhi file mein hain.

**Short names**
- **M-xx** = `docs/manual-actions.md`
- **P-xx, X-xx, S-xx, H-xx** = `docs/prompt.md`
- **Deploy steps** = `docs/deployment-guide.md`
- **Baad ka kaam** = `docs/operations-guide.md`
- Tasks aur schedule: `docs/task.md` | Design: `docs/architecture.md` | Kaun sa Claude model kahan: `docs/model-guide.md`

**Rules:** har P/S/X/H prompt ek **naye** Antigravity session mein. Har task ke baad commit + tag push (message `docs/prompt.md` mein). Auditor (SI) kabhi wo session nahi chalata jisme build hua.

---

## Day 0 (aaj raat, build se pehle)

1. Docs repo mein rakho → **M-08**
2. Hackathon rules aur submission format check → **M-09**
3. `docs/design.md` Claude se banwao (alag se); Day 2 shaam tak `docs/` mein chahiye → **M-08**
4. Model download → **M-05**, datasets download → **M-06** (raat mein ho jaye toh Day 1 bachega)

## Day 1: Foundation

1. VM → **M-01**
2. Docker → **M-02**
3. Git aur GitHub → **M-03**
4. Antigravity → **M-04**, model chunna → `model-guide.md`
5. Kickoff (code nahi) → **P-00**
6. Bootstrap + compose + hardening → **P-01**
7. Secrets banao → **M-07**
8. Hardening audit → **S-01** + **M-11**, fix karwao
9. Model service → **P-02**
10. Gateway core → **P-03**
11. Gateway audit → **S-02** + **M-12**, fix karwao
12. Din ka end: push + tag + VM snapshot → **M-10**

## Day 2: Audit log, runs, agents

1. Standup → **M-24**
2. Logger + verifier → **P-04**
3. Log audit → **S-03** + **M-13**, fix karwao
4. Run lifecycle (commit-reveal) → **P-05**
5. Commit-reveal audit → **S-04** (M-14 ka pehla hissa)
6. Datasets, red/blue agents, bundles → **P-06**
7. Agents aur sealed-data check → **M-14**, phir **M-15** (khud todne ki koshish)
8. `design.md` ready ho gayi? Haan toh frontend Day 3 subah se; nahi toh fallback UI → `prd.md` §6
9. SN ko isolation explain karo → **M-24**
10. Din ka end: push + tag + snapshot → **M-10**

## Day 3: Public API, timing leak, break-it, frontend

1. Standup → **M-24**
2. Public API → **P-07**
3. Timing experiment → **P-08**
4. Timing audit → **S-05** + **M-16**
5. Break-it runner → **P-09**
6. Break-it review → **M-17**
7. Frontend (dusre session mein, parallel) → **P-10**
8. Kuch tootta hai toh → **H-01 / H-02 / H-03 / H-04 / H-05**
9. Stretch sirf agar sab green: seccomp → **X-01**. Slot pinning unreliable ho toh → **X-02**
10. Din ka end: push + tag + snapshot → **M-10**

## Day 4: Ship it

1. Standup → **M-24**
2. Frontend khatam karo → **P-10**
3. Cloud VM aur DNS → **M-18**, **M-19**
4. Production files → **P-11**
5. Server pe deploy → **M-20** (steps: Deploy steps)
6. Deploy ke baad head hash publish → **M-21**
7. Docs aur threat model → **P-12**
8. Final adversarial review → **S-06**
9. Fresh-clone final check → **P-13**
10. Screenshots, video, PPT → **M-22**
11. Demo rehearsal aur pre-demo checklist → Baad ka kaam (section 11)
12. Submission → **M-23**

## Agar peeche ho jao

- Cut list dekho → `task.md` ("Cut list"). MUST items kabhi nahi kaatna.
- Model quota khatam ho raha hai → `model-guide.md` ("Quota kam ho toh")
- Agent bhatak gaya → **H-03**

## Submission ke baad

- Rozmarra kaam, backup, secrets, demo checklist → Baad ka kaam
- Rollback ya troubleshooting → Deploy steps

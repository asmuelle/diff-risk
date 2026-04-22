# 🛠️ Specification: `diff-risk`
**Subtitle:** *Semantic Risk Scoring & Vulnerability Detection for AI-Generated Diffs*

## 1. Core Philosophy
`diff-risk` is based on the premise that **not all lines of code are created equal**. A change to a CSS class is low risk; a change to a `Mutex` lock order is high risk. 

Instead of generic linting, `diff-risk` identifies **"Hot Zones"**—specific patterns in Rust that are historically prone to failure when modified by LLMs. It assigns a risk score (0–10) to a diff, forcing the developer to slow down and think when the AI touches "danger zones."

---

## 2. The Risk Matrix (Semantic Analysis)

`diff-risk` doesn't just see text; it identifies semantic patterns. It flags the following "Danger Zones":

### A. API Contract Violations (Score: 🔴 High)
*   **Pattern:** Changes to `pub` function signatures, modified return types, or changed visibility modifiers.
*   **Risk:** Breaking downstream dependencies or public-facing API contracts.
*   **Detection:** Detects changes in the `pub` keyword or function signature in `lib.rs` or module entry points.

### B. Async Boundaries & Polling (Score: 🔴 High)
*   **Pattern:** Introducing `.await` inside a loop, changing `async` to sync (or vice versa), or modifying `Future` implementations.
*   **Risk:** Deadlocks, "async-sync" impedance mismatch, or blocking the executor (e.g., calling `std::thread::sleep` inside a Tokio task).
*   **Detection:** Scans for changes involving `.await`, `block_on`, `spawn`, and `poll`.

### C. Serde & Schema Drift (Score: 🟡 Medium/High)
*   **Pattern:** Renaming fields in a struct that derives `Serialize` or `Deserialize`, or changing a field type (e.g., `u32` $\rightarrow$ `u64`).
*   **Risk:** Breaking wire-compatibility with other services or failing to deserialize existing database records.
*   **Detection:** Cross-references modified structs with `#[derive(Serialize, Deserialize)]` or `#[serde(rename = "...")]`.

### D. Auth & Permission Gates (Score: 🔴 Critical)
*   **Pattern:** Modifications to functions containing keywords like `authorize`, `authenticate`, `permission`, `role`, or `JWT`.
*   **Risk:** Accidental privilege escalation or bypassing security middleware.
*   **Detection:** Keyword-weighted analysis combined with call-graph distance to the request handler.

### E. Concurrency & Memory Safety (Score: 🔴 High)
*   **Pattern:** Changing `Mutex` to `RwLock`, modifying `Arc` cloning logic, or adding `unsafe` blocks.
*   **Risk:** Race conditions, deadlocks, or memory corruption.
*   **Detection:** Flags any change to `std::sync` or `tokio::sync` primitives.

---

## 3. CLI Interface (UX)

```bash
# Score the current staged changes
diff-risk

# Score a specific commit or PR
diff-risk --commit a1b2c3d

# Set a risk threshold: exit with error if risk is > 7 (for CI/CD)
diff-risk --threshold 7
```

### Example Output:
```text
🚩 DIFF RISK ASSESSMENT: [SCORE: 8.2/10 - HIGH RISK]

⚠️ HIGH RISK: Async Boundary Change
- src/worker.rs: Line 42: Added `.await` inside a critical section.
- Potential: Possible deadlock or executor starvation.

⚠️ HIGH RISK: API Contract Change
- src/lib.rs: Line 112: Changed `fn get_user(id: u32)` -> `fn get_user(id: uuid::Uuid)`.
- Potential: Breaking change for all downstream crates.

🟡 MEDIUM RISK: Serde Schema Drift
- src/models.rs: Line 20: Renamed field `user_name` to `username`.
- Potential: Incompatibility with stored JSON in MongoDB.

✅ LOW RISK: Logic/Syntax
- src/utils.rs: Refactored string concatenation.
```

---

## 4. The Complete "Vibe Coding" Stack

With `diff-risk` added, you now have a professional-grade AI development loop:

| Tool | Role | Logic | Vibe |
| :--- | :--- | :--- | :--- |
| **`cargo-context`** | **The Input** | `Diff` $\rightarrow$ `Context Pack` | *"Give the AI exactly what it needs to be smart."* |
| **`diff-risk`** | **The Filter** | `Diff` $\rightarrow$ `Risk Score` | *"Wait, did the AI just break our auth logic?"* |
| **`cargo-impact`** | **The Proof** | `Change` $\rightarrow$ `Blast Radius` | *"I'll run exactly these 3 tests to be sure."* |

### The Integrated Workflow:
1.  **Draft:** Use `cargo-context` to feed the AI the state $\rightarrow$ AI generates a fix.
2.  **Skepticism:** Run `diff-risk`. 
    *   *If Score < 5:* Move to verification.
    *   *If Score > 5:* Feed the risk report back to the AI: *"You changed the Serde schema, which will break our DB. Fix this to be backward compatible."*
3.  **Verification:** Run `cargo-impact --test` to surgically verify the blast radius.
4.  **Ship:** Commit with confidence.

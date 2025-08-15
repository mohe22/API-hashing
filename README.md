# API-hashing

---

# 🔒 Windows API Hashing – Dynamic Function Resolution

This project demonstrates how to resolve Windows API functions dynamically using **custom hashing** instead of storing API names in plain text. It helps avoid detection by AV and static analysis tools.

### 🧰 Features

* Custom hash function to obfuscate API names
* Manual parsing of PE headers to locate exports
* Resolves `LoadLibraryA` without IAT
* Generic function resolver via hashed names

### 🚀 Usage

1. Include `HashResolver.h` in your project.
2. Call `CalculateHash("FunctionName")` to get the hash.
3. Use `ResolveFunctionByHash("module.dll", HASH)` to get the function pointer.

### 📎 Example

```cpp
auto VirtualAllocPtr = (pVirtualAlloc)ResolveFunctionByHash("kernel32.dll", 0x123456);
```

> 📝 Replace `0x123456` with the hash of the desired API using `CalculateHash`.

---

🔗 **Read the detailed breakdown here:**
[API Hashing Blog](https://portfolio-three-alpha-27.vercel.app/Blogs/api-hashing)

---

This technique is often used in malware for stealth and dynamic resolution—understand it to defend against it.


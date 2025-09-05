# WebProbe

**WebProbe** is a modern, command-line network probing tool written in Java 21.  
It leverages packet capturing, DNS querying, and IP address analysis to inspect and analyze network behavior from the terminal.

> Possible future name: **NetProbe**

---

## 🚀 Features

- 🧰 CLI interface built with [Picocli](https://picocli.info/)
- 📡 Live packet capturing with [Pcap4J](https://www.pcap4j.org/)
- 🌐 DNS querying using [dnsjava](https://github.com/dnsjava/dnsjava)
- 🧠 IP address manipulation with [IPAddress library](https://github.com/seancfoley/IPAddress)
- 📦 JSON output powered by [Jackson Databind](https://github.com/FasterXML/jackson)
- 🧪 Unit tested with [JUnit 5](https://junit.org/junit5/)

---

## 📦 Requirements

- **Java 21**
- **Maven 3.8+**
- (Optional) Native access for packet capturing (requires libpcap on Unix or WinPcap/Npcap on Windows)

---

## 🔧 Build Instructions

```bash
# Clone the repository
git clone https://github.com/AsterExcrisys/web_probe.git
cd web_probe

# Build the project
mvn clean package
````

---

## 📁 Project Structure

```
web_probe/
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/asterexcrisys/webprobe/
│   └── test/
│       └── java/
│           └── com/asterexcrisys/webprobe/
├── pom.xml
├── LICENSE
└── README.md
```

---

## 📄 License

This project is licensed under the **GNU GPLv3 License**.
See the [LICENSE](LICENSE) file for details.

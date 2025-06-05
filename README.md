<!-- Include your logo image here with rounded corners -->
<p align="center">
  <img
    src="./images/Logo.png"
    alt="ContainerSpy Logo"
    width="200"
    style="border-radius:12px;"
  >
</p>


# 🐳 ContainerSpy: Container Activity Auditing & Detection with eBPF

## 🎯 Project Overview

**ContainerSpy** is a Bachelor’s Thesis–level tool for **auditing**, **suspicious-behavior detection**, and **event visualization** inside Linux containers. It focuses on **kernel namespaces**, **cgroups**, and **process–kernel interactions**, providing deep visibility into container activity.

Built on modern observability technologies—**eBPF**, **Prometheus**, **Grafana**—and deployed on a **hand-managed Kubernetes cluster**, ContainerSpy offers fine-grained control and transparency across your container runtime.

---

## 🕵️‍♂️ What ContainerSpy Monitors

- Creation of containers and kernel namespaces  
- Changes to cgroups and `mount`, `user`, and `pid` namespaces  
- Sensitive system calls (syscalls)  
- Cross-container interactions  
- Potential attack vectors (exploits, namespace escapes)  

---

## 📊 Visualization & Alerting

ContainerSpy converts raw data into structured metrics and logs, which are:

1. **Scraped by Prometheus**  
2. **Visualized in Grafana** via custom dashboards, enabling you to:  
   - Track per-container and per-pod activity  
   - Spot anomalous patterns  
   - Configure alerts for dangerous events  

---

## 🚀 Goals

Demonstrate how low-level observability powered by eBPF can **enhance security and traceability** in Kubernetes environments, overcoming the blind spots of traditional container auditing tools.

---

## 🛠️ How to Use ContainerSpy

Navigate to the >bpf/ directory and run:
```
make clean
make
```

Navigate to the >src/ directory and compile the main loader:
```
make clean
make
```

Once everything is built, execute the binary with root privileges: sudo ./main



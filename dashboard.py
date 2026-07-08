import streamlit as st
import subprocess
import json
import os
import shlex

# Sayfa yapılandırması
st.set_page_config(page_title="Tehdit Yüzeyi Tarama Aracı", page_icon="🔍", layout="wide")

# Beyaz pastel tema CSS'i
st.markdown("""
<style>
    /* Ana arkaplan */
    .stApp {
        background-color: #fcfcfc;
    }
    
    /* Yan panel */
    [data-testid="stSidebar"] {
        background-color: #f5f6f8;
        border-right: 1px solid #e0e4e8;
    }

    /* Başlıklar */
    h1, h2, h3, h4, h5, h6 {
        color: #4a5568 !important;
    }
    
    /* Metin rengi */
    .stMarkdown, .stText, p {
        color: #4a5568 !important;
    }

    /* Input alanları */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input {
        background-color: #ffffff;
        border: 1px solid #cbd5e0;
        border-radius: 8px;
        color: #4a5568;
    }

    /* Metric kartları, Tablar ve Expander'lar */
    [data-testid="stMetric"], [data-testid="stExpander"], .stTabs {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    
    [data-testid="stExpander"] {
        padding: 0;
    }
    
    .stCodeBlock {
        border-radius: 8px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)


st.title("🔍 Arama Motoru Stili Tehdit Yüzeyi Tarama")
st.markdown("Hedef alan adını veya IP adresini girin, tarama seçeneklerini belirleyin ve sonuçları inceleyin.")

# Arama motoru tarzı ana giriş
col_search, col_btn = st.columns([4, 1])
with col_search:
    target_url = st.text_input("Hedef IP veya Site URL'si", placeholder="Örn: bilecik.edu.tr", label_visibility="collapsed")
with col_btn:
    run_button = st.button("Taramayı Başlat 🚀", use_container_width=True)

# Yan panel: Ayarlar ve Argümanlar
with st.sidebar:
    st.header("⚙️ Tarama Ayarları")
    
    st.subheader("Çıktı Argümanları")
    report_file = st.text_input("Rapor Dosyası (--report)", value="report.txt")
    json_file = st.text_input("JSON Dosyası (--json)", value="report.json")
    
    st.subheader("Aktif Tarama Ayarları")
    active_scan = st.checkbox("Aktif Tarama (--active)", value=True)
    ports = st.text_input("Portlar (--ports)", value="80,443,8080")
    full_ports = st.checkbox("Tüm Portları Tara (--full-ports)", value=False)
    no_nmap = st.checkbox("Nmap Kullanma (--no-nmap)", value=False)
    
    st.subheader("JavaScript ve Dosya Tarama")
    js_any_domain = st.checkbox("JS İçin Herhangi Bir Domaine İzin Ver (--js-any-domain)", value=True)
    max_js = st.number_input("Maksimum JS Dosyası (--max-js)", min_value=1, value=5)
    max_wayback = st.number_input("Maksimum Wayback URL (--max-wayback)", min_value=10, value=200)

if run_button:
    if not target_url:
        st.warning("Lütfen bir hedef URL veya IP girin!")
    else:
        st.info(f"{target_url} hedeflenerek tarama başlatılıyor. Bu işlem biraz zaman alabilir...")
        
        # Argümanları oluşturma
        cmd = ["python", "main.py", target_url]
        
        if report_file:
            cmd.extend(["--report", report_file])
        if json_file:
            cmd.extend(["--json", json_file])
        
        if active_scan:
            cmd.append("--active")
            if ports:
                cmd.extend(["--ports", ports])
            if full_ports:
                cmd.append("--full-ports")
            if no_nmap:
                cmd.append("--no-nmap")
                
        if js_any_domain:
            cmd.append("--js-any-domain")
            
        cmd.extend(["--max-js", str(max_js)])
        cmd.extend(["--max-wayback", str(max_wayback)])

        # Komutu gösterme
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        st.markdown("**Çalıştırılan Komut:**")
        st.code(cmd_str, language="bash")
        
        # Tarama işlemi
        with st.spinner("Tarama çalışıyor, lütfen bekleyin... (Bu işlem dakikalar sürebilir)"):
            try:
                # Scriptin olduğu dizinde çalışması için cwd ayarlıyoruz
                project_dir = os.path.dirname(os.path.abspath(__file__))
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_dir)
                
                if result.returncode != 0:
                    st.error("Çalıştırma sırasında bir hata oluştu veya komut eksik!")
                    with st.expander("Hata Detayları"):
                        st.code(result.stderr)
                else:
                    st.success("Tarama başarıyla tamamlandı!")
                    
                    json_path = os.path.join(project_dir, json_file)
                    
                    # Sonuçları JSON'dan okuma
                    if os.path.exists(json_path):
                        with open(json_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            
                        # JSON Verilerini Gösterme
                        st.header("📊 Tarama Sonuçları")
                        
                        st.subheader("Genel İstatistikler")
                        col1, col2, col3, col4 = st.columns(4)
                        col1.metric("Hedef Domain", data.get("domain", target_url))
                        col2.metric("Açık Portlar", len(data.get("active_scan", {}).get("open", [])))
                        col3.metric("Uç Noktalar (Endpoints)", len(data.get("endpoints", [])))
                        col4.metric("Alt Alan Adları", len(data.get("subdomains", [])))
                        
                        tabs = st.tabs([
                            "Temel Ağ", "HTTP & Güvenlik", "Zafiyetler & Riskler", 
                            "Keşif (Endpoints vb.)", "Araçlar & Notlar", "Raw JSON"
                        ])
                        
                        with tabs[0]:
                            st.markdown("### 🌐 DNS Kayıtları")
                            st.json(data.get("dns", {}))
                            st.markdown("### 🔌 Aktif Tarama (Açık Portlar)")
                            st.json(data.get("active_scan", {}))
                            st.markdown("### ℹ️ WHOIS")
                            st.text(data.get("whois", {}).get("stdout", "Kayıt bulunamadı."))
                            
                        with tabs[1]:
                            col_h1, col_h2 = st.columns(2)
                            with col_h1:
                                st.markdown("### 📋 HTTP Başlıkları")
                                st.json(data.get("http_headers", {}))
                            with col_h2:
                                st.markdown("### 🛡️ Güvenlik Başlıkları")
                                st.json(data.get("security_headers", {}))
                                
                            st.markdown("### 🔀 CORS Politikası")
                            st.json(data.get("cors", {}))
                            st.markdown("### 🔒 TLS/SSL Bilgisi")
                            st.json(data.get("tls", {}))
                            st.markdown("### ⚙️ Teknoloji Parmak İzi")
                            st.json(data.get("tech_fingerprint", {}))
                            
                        with tabs[2]:
                            st.markdown("### ⚠️ Risk Özeti")
                            st.json(data.get("risk_summary", {}))
                            st.markdown("### 🐛 Olası CVE Eşleşmeleri")
                            cves = data.get("cve_matches", [])
                            if cves:
                                st.table(cves)
                            else:
                                st.info("Herhangi bir CVE eşleşmesi bulunamadı.")
                            
                        with tabs[3]:
                            st.markdown("### 📍 Bulunan Uç Noktalar (Endpoints)")
                            st.write(data.get("endpoints", []))
                            st.markdown("### 🏢 Alt Alan Adları (Subdomains)")
                            st.write(data.get("subdomains", []))
                            st.markdown("### 🔗 Üçüncü Taraf Alan Adları (Third Party)")
                            st.write(data.get("third_party", []))
                            st.markdown("### 🕰️ Wayback URLs")
                            wayback = data.get("wayback_urls", [])
                            with st.expander(f"{len(wayback)} Wayback URL Göster"):
                                st.write(wayback)
                            
                        with tabs[4]:
                            st.markdown("### 🧰 Dış Araç Çıktıları")
                            st.json(data.get("external_tools", {}))
                            st.markdown("### 📝 Notlar")
                            notes = data.get("notes", [])
                            if notes:
                                for note in notes:
                                    st.warning(note)
                            else:
                                st.info("Not bulunmuyor.")
                            
                            st.markdown("### 🤖 robots.txt & sitemap.xml")
                            with st.expander("robots.txt İçeriği"):
                                st.text(data.get("robots") or "robots.txt bulunamadı.")
                            with st.expander("sitemap.xml İçeriği"):
                                st.text(data.get("sitemap") or "sitemap.xml bulunamadı.")
                                
                        with tabs[5]:
                            st.markdown("### 📄 Tam report.json İçeriği")
                            st.json(data)
                            
                    else:
                        st.warning(f"Belirtilen JSON çıktı dosyası ({json_path}) bulunamadı. Lütfen scriptin başarılı çalıştığından emin olun.")
            except Exception as e:
                st.error(f"Bir hata oluştu: {e}")

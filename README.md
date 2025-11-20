<h1 align="center" style="color:#00f5ff;">
   ⚡ NEON LOG INTRUSION ANALYZER – BLUE TEAM SECURITY CONSOLE ⚡
</h1>

<p align="center">
   <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge">
   <img src="https://img.shields.io/badge/Version-1.0-blue?style=for-the-badge">
   <img src="https://img.shields.io/badge/Theme-Neon%20Cyberpunk-%2300f5ff?style=for-the-badge">
</p>

<hr>

<h2 style="color:#00f5ff;">📌 Project Overview</h2>
<p>
   The <strong>Neon Log Intrusion Analyzer</strong> is a fully GUI-based tool designed for 
   analyzing <strong>Apache</strong> and <strong>SSH</strong> logs with a high-tech 
   <span style="color:#00f5ff;">neon cyberpunk</span> interface inspired by classic hacker desktops.
   <br><br>
   This tool helps identify:
</p>

<ul>
   <li>🔥 <strong>SSH Brute Force Attacks</strong></li>
   <li>⚡ <strong>Web Scanning Attempts</strong></li>
   <li>💥 <strong>Potential DoS Activity</strong></li>
   <li>🚨 <strong>Blacklist IP Matches</strong></li>
</ul>

<p>
   The entire UI includes animated neon borders, glowing buttons, Matrix-style boot animation,
   sound effects, and detailed intrusion charts.
</p>

<hr>

<h2 style="color:#00f5ff;">🎨 Interface Preview</h2>

<p>
Below is the primary visual theme inspiration used for the tool:
</p>

<img src="YOUR_SCREENSHOT_LINK" alt="Neon Theme" width="80%">

<p>
Add your GUI screenshots in this section after uploading to GitHub.
</p>

<hr>

<h2 style="color:#00f5ff;">✨ Key Features</h2>

<ul>
   <li><strong>Neon cyberpunk GUI</strong> with glowing cyan borders</li>
   <li><strong>Startup boot sequence</strong> with Matrix falling-code animation</li>
   <li><strong>Sound effects</strong> such as “Access Granted”</li>
   <li><strong>Pulsating neon buttons</strong> and animated frames</li>
   <li><strong>Apache log parsing</strong></li>
   <li><strong>SSH authentication log parsing</strong></li>
   <li><strong>Suspicious activity detection</strong></li>
   <li><strong>Vertical bar graphs</strong> with actual IP labels + values</li>
   <li><strong>CSV report exporting</strong></li>
</ul>

<hr>

<h2 style="color:#00f5ff;">📁 Project Structure</h2>

<pre>
log-intrusion-analyzer/
├── logs/
│   ├── apache_access.log
│   └── auth.log
│
├── reports/
│   └── exported alerts (.csv)
│
├── src/
│   ├── main.py              <- Neon GUI + animations
│   ├── parsers.py           <- Apache & SSH parsing
│   ├── detection.py         <- Attack detection engine
│   ├── reporting.py         <- CSV export handler
│   └── __init__.py
│
├── blacklist_ips.txt
├── requirements.txt
└── README.md
</pre>

<hr>

<h2 style="color:#00f5ff;">🚀 How to Run the Project</h2>

<h3>1️⃣ Install Dependencies</h3>

<pre>
pip install -r requirements.txt
</pre>

<h3>2️⃣ Run the Application</h3>

<pre>
cd src
python main.py
</pre>

<hr>

<h2 style="color:#00f5ff;">📝 Sample Logs for Testing</h2>

<p>You can use the provided sample logs in the <code>logs/</code> folder for testing:</p>

<ul>
  <li><strong>apache_access.log</strong> – triggers scanning & DoS alerts</li>
  <li><strong>auth.log</strong> – triggers brute force detection</li>
</ul>

<hr>

<h2 style="color:#00f5ff;">📊 Charts Output</h2>

<p>
All charts are displayed in vertical bar format, similar to this:
</p>

<img src="YOUR_CHART_IMAGE_LINK" width="70%">

<hr>

<h2 style="color:#00f5ff;">🧠 Tech Stack</h2>
<ul>
   <li><strong>Python</strong></li>
   <li><strong>Tkinter</strong> (GUI framework)</li>
   <li><strong>Matplotlib</strong> (visualization)</li>
   <li><strong>Pandas</strong> (data processing)</li>
</ul>

<hr>

<h2 style="color:#00f5ff;">⚡ Future Enhancements</h2>

<ul>
  <li>Terminal-like live log monitoring</li>
  <li>Real-time active attacks dashboard</li>
  <li>Machine-learning based anomaly detection</li>
  <li>Web-based dashboard version</li>
</ul>

<hr>

<h2 style="color:#00f5ff;">⚠️ Disclaimer</h2>

<p>
<strong>This tool is meant ONLY for educational, research, and defensive security purposes.</strong>
<br><br>
You are not allowed to scan or analyze any system, server, or network that you do not own or do not have
explicit written permission to test.
<br><br>
The developer is not responsible for any misuse of this application.
</p>

<hr>

<h3 align="center" style="color:#00f5ff;">💙 Developed with a Neon Cyberpunk Aesthetic</h3>

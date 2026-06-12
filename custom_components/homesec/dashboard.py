*** Begin Patch
*** Update File: custom_components/homesec/dashboard.py
@@
     for ip, flow_count in sorted(ext_ip_connection_count.items(), key=lambda kv: kv[1], reverse=True)[:TOP_N]:
         ext_info = all_external_ips.get(ip, {})
         top_public_ips.append({
+            "display_name": ext_info.get("hostname") or ext_info.get("display_name") or ext_info.get("org") or ip,
             "ip": ip,
             "flows": flow_count,
             "total_octets": ext_ip_octets.get(ip, 0),
             "hostname": ext_info.get("hostname") or "",
             "org": ext_info.get("org") or "",
             "country": ext_info.get("country") or "",
             "country_name": ext_info.get("country_name") or "",
             "blacklisted": ext_info.get("blacklisted", False),
             "rating": ext_info.get("rating") or "",
         })
@@
     for ext_entry in sorted(all_external_ips.values(), key=lambda e: e.get("ip", "")):
         ip = str(ext_entry.get("ip", ""))
         octets = ext_ip_octets.get(ip, 0)
         external_ips_payload.append({
-            **ext_entry,
-            "total_octets": octets,
-            "total_kb": round(octets / 1024.0, 1),
+            **ext_entry,
+            "display_name": ext_entry.get("hostname") or ext_entry.get("display_name") or ext_entry.get("org") or ip,
+            "total_octets": octets,
+            "total_kb": round(octets / 1024.0, 1),
         })
*** End Patch

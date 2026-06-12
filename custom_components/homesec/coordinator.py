*** Begin Patch
*** Update File: custom_components/homesec/coordinator.py
@@
     def _build_ext_ip_entry(self, ip: str) -> dict[str, object]:
         enrichment = self._enricher.get(ip)
         hostname = self._resolver.get_hostname(ip)
         blacklist = self._resolver.check(ip)
         hostname_threat = self._resolver.check(hostname) if hostname else None
         threat = blacklist or hostname_threat
         entry: dict[str, object] = {
             "ip": ip,
             "hostname": hostname,
             "blacklisted": threat is not None,
             "blacklist_info": threat,
             **enrichment,
         }
+        # Friendly display name: prefer reverse-DNS/device hostname, then enrichment display_name/org/as_name, then raw IP
+        entry["display_name"] = (
+            hostname
+            or enrichment.get("display_name")
+            or enrichment.get("org")
+            or enrichment.get("as_name")
+            or ip
+        )
@@
     async def lookup_ip(self, ip: str) -> dict[str, object]:
         """On-demand enrichment + DNS lookup for a specific IP (used by the lookup endpoint)."""
         hostname = await self._resolver.resolve(ip)
         self._resolver._hostname_cache[ip] = hostname
         enrichment = await self._enricher.enrich_now(ip)
         blacklist = self._resolver.check(ip)
         hostname_threat = self._resolver.check(hostname) if hostname else None
         threat = blacklist or hostname_threat
         entry: dict[str, object] = {
             "ip": ip,
             "hostname": hostname,
             "blacklisted": threat is not None,
             "blacklist_info": threat,
             **enrichment,
         }
+        # Provide display_name for UI convenience (same precedence as _build_ext_ip_entry)
+        entry["display_name"] = (
+            hostname
+            or enrichment.get("display_name")
+            or enrichment.get("org")
+            or enrichment.get("as_name")
+            or ip
+        )
*** End Patch

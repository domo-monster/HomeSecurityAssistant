"""Domain content-category lookup for the HomeSec DNS proxy.

Used to classify queried domain names into broad content categories
(adult, gambling, ads, tracking, social, gaming, streaming, news, …).
Category "malware" is assigned externally by dns_proxy.py when a domain
matches the threat-intelligence blacklist; it is not produced by this module.

The lookup is purely local and static — no network calls are made.
Matching is suffix-based (longest match wins): e.g. "www.pornhub.com" is
matched first against "www.pornhub.com", then "pornhub.com", then "com".

Exported symbols
----------------
CATEGORY_LABELS  — dict[str, str]  human-readable label per category key
KNOWN_CATEGORIES — frozenset[str]  all known category keys
categorize_domain(domain: str) -> str
    Returns a category key string; falls back to "other".
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Category metadata
# ---------------------------------------------------------------------------

#: Human-readable labels for each category key.
CATEGORY_LABELS: dict[str, str] = {
    "malware":   "Malware",
    "adult":     "Adult",
    "gambling":  "Gambling",
    "ads":       "Ads",
    "tracking":  "Tracking",
    "social":    "Social",
    "gaming":    "Gaming",
    "streaming": "Streaming",
    "news":      "News",
    "other":     "Other",
}

KNOWN_CATEGORIES: frozenset[str] = frozenset(CATEGORY_LABELS)

# ---------------------------------------------------------------------------
# Suffix → category map
# Keys are bare domain suffixes (no leading dot).  Matching is tried from
# the most-specific suffix to the least-specific (TLD).
# ---------------------------------------------------------------------------
_SUFFIX_MAP: dict[str, str] = {

    # ── Adult ────────────────────────────────────────────────────────────────
    "pornhub.com":          "adult",
    "xvideos.com":          "adult",
    "xhamster.com":         "adult",
    "xnxx.com":             "adult",
    "xnxx-cdn.com":         "adult",
    "brazzers.com":         "adult",
    "redtube.com":          "adult",
    "youporn.com":          "adult",
    "tube8.com":            "adult",
    "livejasmin.com":       "adult",
    "chaturbate.com":       "adult",
    "onlyfans.com":         "adult",
    "fapello.com":          "adult",
    "erome.com":            "adult",
    "spankbang.com":        "adult",
    "tnaflix.com":          "adult",
    "drtuber.com":          "adult",
    "porn.com":             "adult",
    "porntrex.com":         "adult",
    "hentaihaven.xxx":      "adult",
    "slutload.com":         "adult",
    "beeg.com":             "adult",
    "bang.com":             "adult",
    "reality-kings.com":    "adult",
    "bangbros.com":         "adult",
    # Adult TLDs (catch-all for any domain under these TLDs)
    "xxx":                  "adult",
    "adult":                "adult",
    "sex":                  "adult",
    "porn":                 "adult",

    # ── Gambling ─────────────────────────────────────────────────────────────
    "bet365.com":           "gambling",
    "pokerstars.com":       "gambling",
    "888casino.com":        "gambling",
    "888sport.com":         "gambling",
    "888holdings.com":      "gambling",
    "betway.com":           "gambling",
    "ladbrokes.com":        "gambling",
    "williamhill.com":      "gambling",
    "bwin.com":             "gambling",
    "unibet.com":           "gambling",
    "draftkings.com":       "gambling",
    "fanduel.com":          "gambling",
    "betonline.ag":         "gambling",
    "bovada.lv":            "gambling",
    "betfair.com":          "gambling",
    "pointsbet.com":        "gambling",
    "caesars.com":          "gambling",
    "borgataonline.com":    "gambling",
    "partycasino.com":      "gambling",
    "paddy-power.com":      "gambling",
    "betvictor.com":        "gambling",
    "coral.co.uk":          "gambling",
    "skybet.com":           "gambling",
    "mrgreen.com":          "gambling",
    "casumo.com":           "gambling",
    "leovegas.com":         "gambling",
    "pokerfull.com":        "gambling",
    "partypoker.com":       "gambling",

    # ── Ads ───────────────────────────────────────────────────────────────────
    "doubleclick.net":          "ads",
    "googlesyndication.com":    "ads",
    "googleadservices.com":     "ads",
    "adnxs.com":                "ads",
    "advertising.com":          "ads",
    "taboola.com":              "ads",
    "outbrain.com":             "ads",
    "criteo.com":               "ads",
    "criteo.net":               "ads",
    "amazon-adsystem.com":      "ads",
    "moatads.com":              "ads",
    "adroll.com":               "ads",
    "rubiconproject.com":       "ads",
    "pubmatic.com":             "ads",
    "openx.net":                "ads",
    "smaato.net":               "ads",
    "medianet.com":             "ads",
    "adcolony.com":             "ads",
    "appnexus.com":             "ads",
    "mopub.com":                "ads",
    "inmobi.com":               "ads",
    "tradedoubler.com":         "ads",
    "adfarm.mediaplex.com":     "ads",
    "contextweb.com":           "ads",
    "casalemedia.com":          "ads",
    "yieldmanager.com":         "ads",
    "serving-sys.com":          "ads",
    "smartadserver.com":        "ads",
    "33across.com":             "ads",
    "bidswitch.net":            "ads",
    "adsrvr.org":               "ads",
    "lijit.com":                "ads",
    "sonobi.com":               "ads",
    "sharethrough.com":         "ads",
    "teads.tv":                 "ads",

    # ── Tracking ──────────────────────────────────────────────────────────────
    "google-analytics.com":     "tracking",
    "googletagmanager.com":     "tracking",
    "googletagservices.com":    "tracking",
    "hotjar.com":               "tracking",
    "mixpanel.com":             "tracking",
    "segment.com":              "tracking",
    "segment.io":               "tracking",
    "amplitude.com":            "tracking",
    "heap.io":                  "tracking",
    "fullstory.com":            "tracking",
    "logrocket.com":            "tracking",
    "newrelic.com":             "tracking",
    "nr-data.net":              "tracking",
    "mouseflow.com":            "tracking",
    "statcounter.com":          "tracking",
    "clicky.com":               "tracking",
    "scorecardresearch.com":    "tracking",
    "quantserve.com":           "tracking",
    "chartbeat.com":            "tracking",
    "parsely.com":              "tracking",
    "kissmetrics.com":          "tracking",
    "intercom.io":              "tracking",
    "intercom.com":             "tracking",
    "crazyegg.com":             "tracking",
    "pingdom.net":              "tracking",
    "pingdom.com":              "tracking",
    "branch.io":                "tracking",
    "appsflyer.com":            "tracking",
    "adjust.com":               "tracking",
    "kochava.com":              "tracking",
    "mparticle.com":            "tracking",
    "omtrdc.net":               "tracking",
    "demdex.net":               "tracking",
    "2o7.net":                  "tracking",
    "omniture.com":             "tracking",
    "adobedtm.com":             "tracking",
    "launchdarkly.com":         "tracking",
    "optimizely.com":           "tracking",
    "vwo.com":                  "tracking",

    # ── Social ────────────────────────────────────────────────────────────────
    "facebook.com":             "social",
    "fbcdn.net":                "social",
    "fbsbx.com":                "social",
    "fb.com":                   "social",
    "instagram.com":            "social",
    "cdninstagram.com":         "social",
    "twitter.com":              "social",
    "t.co":                     "social",
    "twimg.com":                "social",
    "x.com":                    "social",
    "tiktok.com":               "social",
    "tiktokv.com":              "social",
    "tiktokcdn.com":            "social",
    "musically.com":            "social",
    "snapchat.com":             "social",
    "sc-cdn.net":               "social",
    "pinterest.com":            "social",
    "pinimg.com":               "social",
    "linkedin.com":             "social",
    "licdn.com":                "social",
    "reddit.com":               "social",
    "redd.it":                  "social",
    "redditmedia.com":          "social",
    "reddituploads.com":        "social",
    "tumblr.com":               "social",
    "discord.com":              "social",
    "discordapp.com":           "social",
    "discordapp.net":           "social",
    "whatsapp.com":             "social",
    "whatsapp.net":             "social",
    "telegram.org":             "social",
    "t.me":                     "social",
    "mastodon.social":          "social",
    "bsky.app":                 "social",
    "bsky.social":              "social",
    "vk.com":                   "social",
    "vk.me":                    "social",
    "ok.ru":                    "social",
    "weibo.com":                "social",
    "wechat.com":               "social",
    "wx.qq.com":                "social",
    "line.me":                  "social",
    "kakao.com":                "social",
    "viber.com":                "social",
    "signal.org":               "social",

    # ── Gaming ────────────────────────────────────────────────────────────────
    "steampowered.com":         "gaming",
    "steamcommunity.com":       "gaming",
    "steamstatic.com":          "gaming",
    "steamusercontent.com":     "gaming",
    "epicgames.com":            "gaming",
    "unrealengine.com":         "gaming",
    "roblox.com":               "gaming",
    "rbxcdn.com":               "gaming",
    "ea.com":                   "gaming",
    "origin.com":               "gaming",
    "battle.net":               "gaming",
    "blizzard.com":             "gaming",
    "minecraft.net":            "gaming",
    "mojang.com":               "gaming",
    "playfab.com":              "gaming",
    "xboxlive.com":             "gaming",
    "xbox.com":                 "gaming",
    "playstation.com":          "gaming",
    "psn.com":                  "gaming",
    "nintendo.com":             "gaming",
    "gog.com":                  "gaming",
    "ubisoft.com":              "gaming",
    "ubi.com":                  "gaming",
    "activision.com":           "gaming",
    "riotgames.com":            "gaming",
    "valorant.com":             "gaming",
    "leagueoflegends.com":      "gaming",
    "2k.com":                   "gaming",
    "rockstargames.com":        "gaming",
    "bethesda.net":             "gaming",
    "bethesda.com":             "gaming",
    "cdprojektred.com":         "gaming",
    "cdprojekt.com":            "gaming",
    "kongregate.com":           "gaming",
    "poki.com":                 "gaming",
    "itch.io":                  "gaming",
    "gameloft.com":             "gaming",
    "supercell.com":            "gaming",

    # ── Streaming ─────────────────────────────────────────────────────────────
    "netflix.com":              "streaming",
    "nflximg.net":              "streaming",
    "nflxvideo.net":            "streaming",
    "nflxext.com":              "streaming",
    "nflxso.net":               "streaming",
    "youtube.com":              "streaming",
    "youtu.be":                 "streaming",
    "googlevideo.com":          "streaming",
    "ytimg.com":                "streaming",
    "yt3.ggpht.com":            "streaming",
    "hulu.com":                 "streaming",
    "hulustream.com":           "streaming",
    "disneyplus.com":           "streaming",
    "bamgrid.com":              "streaming",
    "primevideo.com":           "streaming",
    "aiv-cdn.net":              "streaming",
    "amazonvideo.com":          "streaming",
    "spotify.com":              "streaming",
    "scdn.co":                  "streaming",
    "spotifycdn.com":           "streaming",
    "soundcloud.com":           "streaming",
    "sndcdn.com":               "streaming",
    "vimeo.com":                "streaming",
    "vimeocdn.com":             "streaming",
    "deezer.com":               "streaming",
    "tidal.com":                "streaming",
    "jtvnw.net":                "streaming",
    "plex.tv":                  "streaming",
    "plexapp.com":              "streaming",
    "dailymotion.com":          "streaming",
    "crunchyroll.com":          "streaming",
    "funimation.com":           "streaming",
    "paramountplus.com":        "streaming",
    "discoveryplus.com":        "streaming",
    "hbomax.com":               "streaming",
    "max.com":                  "streaming",
    "peacocktv.com":            "streaming",
    "appletv.apple.com":        "streaming",
    "mzstatic.com":             "streaming",

    # ── News ──────────────────────────────────────────────────────────────────
    "cnn.com":                  "news",
    "bbc.com":                  "news",
    "bbc.co.uk":                "news",
    "bbci.co.uk":               "news",
    "nytimes.com":              "news",
    "theguardian.com":          "news",
    "reuters.com":              "news",
    "apnews.com":               "news",
    "washingtonpost.com":       "news",
    "foxnews.com":              "news",
    "nbcnews.com":              "news",
    "cbsnews.com":              "news",
    "bloomberg.com":            "news",
    "forbes.com":               "news",
    "techcrunch.com":           "news",
    "theverge.com":             "news",
    "arstechnica.com":          "news",
    "engadget.com":             "news",
    "wired.com":                "news",
    "gizmodo.com":              "news",
    "mashable.com":             "news",
    "zdnet.com":                "news",
    "theregister.com":          "news",
    "abcnews.go.com":           "news",
    "msn.com":                  "news",
    "usatoday.com":             "news",
    "time.com":                 "news",
    "economist.com":            "news",
    "ft.com":                   "news",
    "lemonde.fr":               "news",
    "lefigaro.fr":              "news",
    "spiegel.de":               "news",
    "faz.net":                  "news",
    "corriere.it":              "news",
    "elpais.com":               "news",
    "marca.com":                "news",
}


def categorize_domain(domain: str) -> str:
    """Return the content category for *domain* using longest-suffix matching.

    Tries suffixes from most-specific to least-specific (TLD).
    Falls back to ``"other"`` if no suffix matches.

    Examples::

        categorize_domain("www.pornhub.com")   # -> "adult"
        categorize_domain("something.xxx")     # -> "adult"
        categorize_domain("ads.doubleclick.net") # -> "ads"
        categorize_domain("example.com")       # -> "other"
    """
    if not domain:
        return "other"
    parts = domain.lower().rstrip(".").split(".")
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        cat = _SUFFIX_MAP.get(candidate)
        if cat is not None:
            return cat
    return "other"

"""Read-only server overview. Reuses the panel's authentication and LAN guards."""
import os
import time
from flask import jsonify, render_template


def attach(p):
    @p.app.get('/server')
    def server_center():
        return render_template('server.html')

    @p.app.get('/api/server/health')
    def server_health():
        mem = p.psutil.virtual_memory()
        disks, warnings = [], []
        for part in p.psutil.disk_partitions(all=False):
            if part.fstype in {'squashfs', 'tmpfs', 'devtmpfs', 'overlay'}:
                continue
            try:
                usage = p.psutil.disk_usage(part.mountpoint)
                disks.append(dict(device=part.device, mount=part.mountpoint,
                                  filesystem=part.fstype, total=usage.total,
                                  used=usage.used, free=usage.free, percent=usage.percent))
                if usage.percent >= 85:
                    warnings.append('المساحة قاربت الامتلاء: ' + part.mountpoint)
            except OSError:
                warnings.append('تعذرت قراءة القرص: ' + part.mountpoint)
        temperatures = []
        try:
            for group in p.psutil.sensors_temperatures().values():
                temperatures.extend(t.current for t in group if t.current is not None)
        except (AttributeError, OSError):
            pass
        services = {}
        for name in ('moh-files', 'smbd', 'xrdp', 'ssh', 'dnsmasq', 'share-internet', 'kali-net-panel', 'kali-net-panel-http'):
            try:
                result = p.run(['systemctl', 'is-active', name], check=False)
                services[name] = result.stdout.strip() or 'unknown'
            except (OSError, RuntimeError):
                services[name] = 'unknown'
        if mem.percent >= 85:
            warnings.append('استهلاك الذاكرة مرتفع')
        return jsonify(cpu=p.psutil.cpu_percent(interval=0.1),
                       memory=dict(total=mem.total, used=mem.used, percent=mem.percent),
                       uptime=max(0, time.time() - p.psutil.boot_time()),
                       temperature=max(temperatures) if temperatures else None,
                       load=list(os.getloadavg()) if hasattr(os, 'getloadavg') else None,
                       disks=disks, services=services, warnings=warnings,
                       sampled_at=time.time())

    from app_hub import attach as attach_hub
    attach_hub(p)

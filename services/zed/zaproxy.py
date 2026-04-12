
from zapv2 import ZAPv2
import time

class ZapScanner:
    def __init__(self, target, api_key):
        self.scan_id = None
        self.target = target
        self.api_key = api_key
        self.zap = ZAPv2(apikey=self.api_key)

    #ajax spider based method to explore the app for any js populated content or xss attacks possibility
    def exploring_app(self):
        if self.api_key is None:
            print("No API key provided")
            return

        self.scan_id = self.zap.ajaxSpider.scan(self.target)
        start_time = time.time()
        while self.zap.ajaxSpider.status != 'stopped':
            if time.time() - start_time > 120:  # 2 minutes timeout
                self.zap.ajaxSpider.stop()
                print("Ajax spider timed out.")
                break
            print('Ajax Spider status: ' + self.zap.ajaxSpider.status)
            time.sleep(2)

        print("Ajax spider completed")

    #active scanning
    def active_scan(self):
        if self.api_key is None:
            print("No API key provided")
            return
        self.scan_id = self.zap.ascan.scan(self.target)
        while int(self.zap.ascan.status(self.scan_id)) < 100:
            print('Scan progress %: {}'.format(self.zap.ascan.status(self.scan_id)))
            time.sleep(5)
        print("Active scan completed")
        return self.zap.alert.alerts(baseurl=self.target, start=0, count=5000)
    def collect_alerts(self):
        alert_dict = []
        st = 0
        pg = 500
        blacklist = [1, 2]
        alerts = self.zap.alert.alerts(baseurl=self.target, start=st, count=pg)

        while len(alerts) > 0:
            print('Reading {} alerts from {}'.format(pg, st))
            for alert in alerts:
                plugin_id = int(alert.get('pluginId'))
                if plugin_id in blacklist:
                    continue
                if alert.get('risk') == 'Informational':
                    continue
                alert_dict.append({
                    "risk": alert.get('risk'),
                    "name": alert.get('name'),
                    "url": alert.get('url'),
                    "description": alert.get('description'),
                    "solution": alert.get('solution')
                })
            st += pg
            alerts = self.zap.alert.alerts(baseurl=self.target, start=st, count=pg)

        return alert_dict

    #returning the alerts arr after initiating exploration and active scanning
    def results(self):
        self.exploring_app()
        scan_id = self.zap.spider.scan(self.target)
        while int(self.zap.spider.status(scan_id)) < 100:
            print("Spider progress:", self.zap.spider.status(scan_id))
            time.sleep(2)

        while int(self.zap.pscan.records_to_scan) > 0:
            print("Remaining:", self.zap.pscan.records_to_scan)
            time.sleep(2)

        print("Starting active scan")
        self.active_scan()

        print("Collecting alerts")
        return self.collect_alerts()


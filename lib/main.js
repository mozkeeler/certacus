let events = require("sdk/system/events");
let ss = require("sdk/simple-storage");
let { Cc, Ci } = require("chrome");
let panel = require("sdk/panel");
let widget = require("sdk/widget");
let content = require("sdk/self");

function maybeAddCA(aSubjectName, aFingerprint, aHost) {
  if (!ss.storage.CAs) {
    ss.storage.CAs = {};
  }

  if (!ss.storage.CAs[aFingerprint]) {
    ss.storage.CAs[aFingerprint] = { subjectName: aSubjectName,
                                     fingerprint: aFingerprint,
                                     hosts: [ aHost ],
                                     timestamp: (new Date()).getTime() };
    console.log("added '" + aSubjectName + "' (" + aFingerprint +
                ") with host " + aHost);
  } else {
    let ca = ss.storage.CAs[aFingerprint];
    let found = false;
    for (let host of ca.hosts) {
      if (host == aHost) {
        found = true;
        break;
      }
    }

    if (!found) {
      ca.hosts.push(aHost);
      console.log("added host '" + aHost + "' to " + aSubjectName +
                  "(" + aFingerprint + ")");
    }

    ca.timestamp = (new Date()).getTime();
  }
}

function responseListener(event) {
  let channel = event.subject.QueryInterface(Ci.nsIHttpChannel);
  if (channel.URI.scheme == "https") {
    let si = channel.securityInfo;
    let st = si.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
    let cert = st.QueryInterface(Ci.nsISSLStatus).serverCert;
    let chain = cert.getChain();
    let ca = chain.queryElementAt(chain.length - 1, Ci.nsIX509Cert);
    maybeAddCA(ca.subjectName, ca.sha1Fingerprint, channel.URI.host);
  }
}

function changeTrust(distrusting) {
  if (!ss.storage.savedTrust) {
    ss.storage.savedTrust = {};
  }
  if (distrusting) {
    for (let ca of caList) {
      let trusted = certDB.isCertTrusted(ca, Ci.nsIX509Cert.CA_CERT,
                                         Ci.nsIX509CertDB.TRUSTED_SSL);
      if (!ss.storage.CAs[ca.sha1Fingerprint] && trusted) {
        ss.storage.savedTrust[ca.sha1Fingerprint] = trusted;
        certDB.setCertTrust(ca, Ci.nsIX509Cert.CA_CERT,
                            Ci.nsIX509CertDB.UNTRUSTED);
      }
    }
  } else {
    for (let ca of caList) {
      if (ss.storage.savedTrust[ca.sha1Fingerprint]) {
        certDB.setCertTrust(ca, Ci.nsIX509Cert.CA_CERT,
                            Ci.nsIX509CertDB.TRUSTED_SSL);
      }
    }
  }
}

let hostPanel = panel.Panel({
  contentURL: content.data.url("hostPanel.html"),
  width: 700,
  height: 500,
  onMessage: function(aMessage) {
    let distrusting = (aMessage == "distrust");
    changeTrust(distrusting);
    this.hide();
    this.show();
  },
  onShow: function() {
    this.postMessage({ kind: "reset" });
    for (let ca of caList) {
      let verified = {};
      let usages = {};
      ca.getUsagesString(false, verified, usages);
      if (ss.storage.CAs[ca.sha1Fingerprint])
        this.postMessage({ kind: "used", element: ca.subjectName, usages: usages.value });
      else
        this.postMessage({ kind: "unused", element: ca.subjectName, usages: usages.value });
    }
  }
});

let hostWidget = widget.Widget({
  id: "hostWidget",
  label: "Hosts",
  contentURL: content.data.url("icon16.png"),
  width: 16,
  panel: hostPanel
});

let certDB = Cc["@mozilla.org/security/x509certdb;1"]
               .getService(Ci.nsIX509CertDB);
let caList = [];
exports.main = function main(options, callbacks) {
  let certCache = Cc["@mozilla.org/security/nsscertcache;1"]
                    .createInstance(Ci.nsINSSCertCache);
  certCache.cacheAllCerts();
  let certList = certCache.getX509CachedCerts().getEnumerator();
  while (certList.hasMoreElements()) {
    let cert = certList.getNext().QueryInterface(Ci.nsIX509Cert);
    if (cert.issuerName == cert.subjectName) {
      caList.push(cert);
    }
  }
  events.on("http-on-examine-response", responseListener);
}

exports.onUnload = function onUnload(reason) {
  if (reason == "uninstall" || reason == "disable") {
    changeTrust(false);
  }
}

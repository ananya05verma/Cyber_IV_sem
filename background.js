chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete' && tab.active) {
        fetch("http://127.0.0.1:5000/check_url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: tab.url })
        })
        .then(response => response.json())
        .then(data => {
            if (data.result === "malicious") {
                chrome.tabs.update(tabId, { url: chrome.runtime.getURL("warning.html") });
            }
        })
        .catch(error => console.error("Error:", error));
    }
});

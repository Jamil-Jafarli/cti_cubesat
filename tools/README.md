# Tools

## Uplink monitor

`uplink_monitor/uplink_monitor.py` shows the frames the uplink transmitter
sends, live, in a browser. Run it on the computer the Pico is connected to:

```sh
python3 tools/uplink_monitor/uplink_monitor.py --serial /dev/ttyACM0
python3 tools/uplink_monitor/uplink_monitor.py --demo      # no hardware
# open http://127.0.0.1:8701
```

It reads the `[up] ...` lines of `firmware/uplink_transmitter`, keeps the last
400 frames in memory and stores nothing on disk. Only the standard library is
needed, plus pyserial for `--serial`. The serial port can be read by only one
program at a time, so stop `analysis/benchlog.py` while the monitor runs.

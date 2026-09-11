#!/bin/sh
# W2.4b plant (benign payload — marker + echo stub, no network, no exfil):
# writes two things npm's own manifest does NOT track and uninstall -g never reverts.
echo 'export RT_W24B_PLANT_MARKER=1' >> /etc/profile
printf '#!/bin/sh\necho rt-plant-orphan\n' > /usr/local/bin/rt-plant-orphan
chmod 755 /usr/local/bin/rt-plant-orphan

import re

with open("CHANGELOG.md", "r") as f:
    lines = f.readlines()

new_lines = []
added_done = False
for line in lines:
    new_lines.append(line)
    if not added_done and line.strip() == "### Added":
        new_lines.append("- **Dual-Asset Support**: Added support for native XLM and SEP-41 tokens in RefundVault.\n")
        new_lines.append("- **Upto-Authorization Fuzzing**: Added extensive fuzz testing limits.\n")
        new_lines.append("- **VDF Slashing Penalty**: Accurate assessment of slashing penalty calculations.\n")
        new_lines.append("- **Time Policy Transitions**: Supported Grace Period and Cooldown transitions.\n")
        added_done = True

with open("CHANGELOG.md", "w") as f:
    f.writelines(new_lines)

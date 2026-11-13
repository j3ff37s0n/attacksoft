"""Battleship SVGs for the radar widget."""
import uuid
import random
import math
from typing import Tuple

def _svg(paths):
    return (
        '<svg viewBox="0 0 200 100" xmlns="http://www.w3.org/2000/svg" '
        'fill="currentColor" stroke="none">' + "".join(paths) + '</svg>'
    )

# 1. Aircraft Carrier
_CARRIER = _svg([
    '<path d="M 10 80 L 190 80 L 180 90 L 20 90 Z" />',
    '<path d="M 20 80 L 30 60 L 170 60 L 180 80 Z" />',
    '<path d="M 60 60 L 70 45 L 90 45 L 90 60 Z" />', # Island
    '<path d="M 40 55 L 50 55 L 50 60 L 40 60 Z" opacity="0.5" />',
    '<path d="M 120 55 L 130 55 L 130 60 L 120 60 Z" opacity="0.5" />',
])

# 2. Battleship
_BATTLESHIP = _svg([
    '<path d="M 10 75 L 190 75 L 180 85 L 20 85 Z" />',
    '<path d="M 40 75 L 50 55 L 150 55 L 160 75 Z" />',
    '<circle cx="70" cy="55" r="8" />', # Turret
    '<circle cx="130" cy="55" r="8" />', # Turret
    '<path d="M 90 75 L 100 50 L 110 75 Z" />', # Bridge
    '<path d="M 95 50 L 105 50 M 100 50 L 100 40" />', # Mast
])

# 3. Destroyer
_DESTROYER = _svg([
    '<path d="M 20 75 L 180 75 L 170 85 L 30 85 Z" />',
    '<path d="M 50 75 L 60 60 L 140 60 L 150 75 Z" />',
    '<path d="M 80 60 L 90 45 L 110 45 L 120 60 Z" />',
    '<circle cx="70" cy="70" r="5" />',
    '<circle cx="130" cy="70" r="5" />',
])

# 4. Submarine
_SUBMARINE = _svg([
    '<path d="M 20 60 Q 20 70 40 70 L 160 70 Q 180 70 180 60 Q 180 50 160 50 L 40 50 Q 20 50 20 60 Z" />',
    '<path d="M 80 50 L 90 35 L 110 35 L 120 50 Z" />', # Sail
    '<path d="M 90 35 L 90 25 M 110 35 L 110 25" />', # Periscopes
    '<circle cx="50" cy="60" r="3" opacity="0.5" />',
    '<circle cx="150" cy="60" r="3" opacity="0.5" />',
])

# 5. Cruiser
_CRUISER = _svg([
    '<path d="M 15 75 L 185 75 L 175 85 L 25 85 Z" />',
    '<path d="M 30 75 L 40 55 L 160 55 L 170 75 Z" />',
    '<path d="M 70 55 L 80 40 L 120 40 L 130 55 Z" />',
    '<path d="M 90 40 L 110 40 M 100 40 L 100 25" />',
    '<circle cx="50" cy="70" r="6" />',
    '<circle cx="150" cy="70" r="6" />',
])

# 6. Frigate
_FRIGATE = _svg([
    '<path d="M 25 75 L 175 75 L 165 85 L 35 85 Z" />',
    '<path d="M 60 75 L 70 55 L 130 55 L 140 75 Z" />',
    '<circle cx="100" cy="55" r="10" />', # Radar dome
    '<path d="M 100 45 L 100 30" />',
    '<circle cx="80" cy="70" r="4" />',
    '<circle cx="120" cy="70" r="4" />',
])

# 7. Corvette
_CORVETTE = _svg([
    '<path d="M 30 75 L 170 75 L 160 85 L 40 85 Z" />',
    '<path d="M 70 75 L 80 60 L 120 60 L 130 75 Z" />',
    '<path d="M 90 60 L 100 45 L 110 60 Z" />',
    '<circle cx="70" cy="70" r="3" />',
    '<circle cx="130" cy="70" r="3" />',
])

# 8. Minesweeper
_MINESWEEPER = _svg([
    '<path d="M 35 75 L 165 75 L 155 85 L 45 85 Z" />',
    '<path d="M 65 75 L 75 60 L 125 60 L 135 75 Z" />',
    '<path d="M 100 60 L 100 40 M 90 40 L 110 40" />', # Crane
    '<circle cx="60" cy="80" r="4" opacity="0.5" />',
    '<circle cx="140" cy="80" r="4" opacity="0.5" />',
])

# 9. Landing Ship
_LANDING = _svg([
    '<path d="M 10 75 L 190 75 L 180 85 L 20 85 Z" />',
    '<path d="M 30 75 L 40 55 L 130 55 L 140 75 Z" />',
    '<path d="M 140 75 L 180 75 L 180 60 L 160 60 Z" />', # Ramp
    '<path d="M 50 55 L 60 45 L 80 45 L 80 55 Z" />',
    '<path d="M 100 55 L 110 45 L 120 45 L 120 55 Z" />',
])

# 10. Patrol Boat
_PATROL = _svg([
    '<path d="M 40 75 L 160 75 L 150 85 L 50 85 Z" />',
    '<path d="M 70 75 L 80 60 L 120 60 L 130 75 Z" />',
    '<path d="M 100 60 L 100 45" />', # Mast
    '<circle cx="100" cy="40" r="4" />', # Light
])

DINOSAURS = [
    _CARRIER,
    _BATTLESHIP,
    _DESTROYER,
    _SUBMARINE,
    _CRUISER,
    _FRIGATE,
    _CORVETTE,
    _MINESWEEPER,
    _LANDING,
    _PATROL,
]

DINO_NAMES = [
    "Aircraft Carrier",
    "Battleship",
    "Destroyer",
    "Submarine",
    "Cruiser",
    "Frigate",
    "Corvette",
    "Minesweeper",
    "Landing Ship",
    "Patrol Boat",
]

def pick(sid: str) -> Tuple[int, bool, str]:
    try:
        n = int(uuid.UUID(sid).int) % 20
    except (ValueError, AttributeError):
        n = 0
    base = n % 10
    flipped = bool(n >= 10)
    return n, flipped, DINOSAURS[base]


def pick_fleet(sid: str) -> list:
    try:
        n = int(uuid.UUID(sid).int)
    except (ValueError, AttributeError):
        n = 0

    rng = random.Random(n)

    # (index in DINOSAURS, name, hit points, scale)
    types = [
        (0, "Aircraft Carrier", 4, 0.55),
        (1, "Battleship", 3, 0.65),
        (2, "Destroyer", 2, 0.75),
        (3, "Submarine", 2, 0.65),
        (9, "Patrol Boat", 1, 0.85),
    ]

    fleet = []
    for i, (d_idx, name, hp, scale) in enumerate(types):
        angle = rng.uniform(0, 2 * math.pi)
        # Keep initial distance small (5-25%) so they stay near the center
        dist = rng.uniform(5, 25) 

        x = 50 + dist * math.cos(angle)
        y = 50 + dist * math.sin(angle)

        ship_angle = rng.uniform(-20, 20)
        flipped = rng.choice([True, False])

        # Drift animation parameters (in SVG coordinate space 0-200)
        # A range of +/- 25 means they drift slightly but never escape the circle
        dx = rng.randint(-25, 25)
        dy = rng.randint(-15, 15)
        duration = rng.uniform(4.0, 9.0)
        anim_id = f"drift-{i}-{n % 1000}"

        raw_svg = DINOSAURS[d_idx]
        inner_paths = raw_svg.split('>', 1)[1].rsplit('<', 1)[0]

        animated_svg = f'''<svg viewBox="0 0 200 100" xmlns="http://www.w3.org/2000/svg" fill="currentColor" stroke="none">
          <style>
            @keyframes {anim_id} {{
              0% {{ transform: translate(0px, 0px); }}
              100% {{ transform: translate({dx}px, {dy}px); }}
            }}
            .{anim_id} {{
              animation: {anim_id} {duration:.1f}s ease-in-out infinite alternate;
            }}
          </style>
          <g class="{anim_id}">
            {inner_paths}
          </g>
        </svg>'''

        fleet.append({
            "svg": animated_svg,
            "name": name,
            "hp": hp,
            "scale": scale,
            "x": round(x, 2),
            "y": round(y, 2),
            "angle": round(ship_angle, 2),
            "flipped": flipped,
        })
    return fleet

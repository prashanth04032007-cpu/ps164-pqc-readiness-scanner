import math

class CentroidTracker:
    def __init__(self, max_distance=120, max_disappeared=20):
        self.next_id = 1
        self.objects = {}
        self.disappeared = {}
        self.max_distance = max_distance
        self.max_disappeared = max_disappeared

    @staticmethod
    def centroid(box):
        x1, y1, x2, y2 = box
        return ((x1+x2)//2, (y1+y2)//2)

    @staticmethod
    def dist(a, b):
        return math.hypot(a[0]-b[0], a[1]-b[1])

    def update(self, boxes):
        if not boxes:
            for oid in list(self.disappeared):
                self.disappeared[oid] += 1
                if self.disappeared[oid] > self.max_disappeared:
                    self.objects.pop(oid, None)
                    self.disappeared.pop(oid, None)
            return {}

        cents = [self.centroid(b) for b in boxes]
        assigned = {}
        used = set()

        # Greedy nearest-centroid assignment, sufficient for MVP.
        for oid, old_cent in list(self.objects.items()):
            best = None
            best_d = self.max_distance
            for i, cent in enumerate(cents):
                if i in used:
                    continue
                d = self.dist(old_cent, cent)
                if d < best_d:
                    best_d, best = d, i

            if best is not None:
                assigned[best] = oid
                used.add(best)
                self.objects[oid] = cents[best]
                self.disappeared[oid] = 0
            else:
                self.disappeared[oid] = self.disappeared.get(oid, 0) + 1
                if self.disappeared[oid] > self.max_disappeared:
                    self.objects.pop(oid, None)
                    self.disappeared.pop(oid, None)

        for i, cent in enumerate(cents):
            if i not in used:
                oid = self.next_id
                self.next_id += 1
                self.objects[oid] = cent
                self.disappeared[oid] = 0
                assigned[i] = oid

        return assigned

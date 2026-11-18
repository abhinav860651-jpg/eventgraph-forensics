import networkx as nx

def calculate_link_confidence(ev1: dict, ev2: dict) -> tuple[float, str]:
    time_diff = (ev2["timestamp"] - ev1["timestamp"]).total_seconds()
    if time_diff < 0 or time_diff > 600:
        return 0.0, ""
    if ev1["device"] != ev2["device"] and "USB" in ev1["event_type"] and "USB" in ev2["event_type"] and time_diff <= 30:
        score = round(max(0.85, 1.0 - (time_diff / 100.0)), 2)
        reason = f"Cross-device USB handshake: {ev1['device']} ({ev1['event_type']}) followed by {ev2['device']} ({ev2['event_type']}) within {int(time_diff)}s."
        return score, reason
    if ev1["actor"] == ev2["actor"] and time_diff <= 300:
        score = round(max(0.50, 0.80 - (time_diff / 1000.0)), 2)
        reason = f"Temporal & actor continuity ({ev1['actor']}): {int(time_diff)}s apart across {ev1['device']} -> {ev2['device']}."
        return score, reason
    return 0.0, ""

def build_event_graph(events: list[dict]) -> nx.DiGraph:
    sorted_events = sorted(events, key=lambda x: x["timestamp"])
    G = nx.DiGraph()
    for ev in sorted_events:
        G.add_node(ev["event_id"], **ev)
    for i in range(len(sorted_events)):
        for j in range(i + 1, len(sorted_events)):
            conf, explanation = calculate_link_confidence(sorted_events[i], sorted_events[j])
            if conf >= 0.50:
                G.add_edge(sorted_events[i]["event_id"], sorted_events[j]["event_id"], confidence=conf, explanation=explanation)
    return G

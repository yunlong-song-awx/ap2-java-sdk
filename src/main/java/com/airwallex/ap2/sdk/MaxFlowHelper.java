package com.airwallex.ap2.sdk;

import com.airwallex.ap2.protocol.CartLineItem;
import com.airwallex.ap2.protocol.LineItem;
import com.airwallex.ap2.protocol.LineItemRequirements;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class MaxFlowHelper {

    private static final int INF = 1_000_000_000;

    private MaxFlowHelper() {}

    static List<String> evaluateLineItemsMaxFlow(
            List<CartLineItem> checkoutItems,
            List<LineItemRequirements> requirements) {
        return evaluateLineItemsMaxFlow(checkoutItems, requirements, "dinic");
    }

    static List<String> evaluateLineItemsMaxFlow(
            List<CartLineItem> checkoutItems,
            List<LineItemRequirements> requirements,
            String mode) {

        Map<String, Integer> cartQty = new HashMap<>();
        for (CartLineItem li : checkoutItems) {
            String sku = li.item().id();
            cartQty.merge(sku, li.quantity(), Integer::sum);
        }

        List<String> skuList = new ArrayList<>(cartQty.keySet());

        List<Set<String>> reqAcceptable = new ArrayList<>();
        List<Boolean> reqIsWildcard = new ArrayList<>();
        for (LineItemRequirements req : requirements) {
            Set<String> acceptable = new HashSet<>();
            if (req.acceptableItems() != null) {
                for (LineItem item : req.acceptableItems()) {
                    acceptable.add(item.id());
                }
            }
            reqAcceptable.add(acceptable);
            reqIsWildcard.add(req.acceptableItems() == null || req.acceptableItems().isEmpty());
        }

        List<String> violations = new ArrayList<>();

        boolean hasWildcard = reqIsWildcard.stream().anyMatch(Boolean::booleanValue);
        Set<String> allAcceptable = new HashSet<>();
        if (!hasWildcard) {
            for (Set<String> acc : reqAcceptable) {
                allAcceptable.addAll(acc);
            }
        }

        for (String sku : skuList) {
            int qty = cartQty.get(sku);
            if (qty <= 0) continue;
            if (!hasWildcard && !allAcceptable.contains(sku)) {
                violations.add("Item " + sku + " not in any requirement's acceptable items");
            }
        }
        if (!violations.isEmpty()) return violations;

        int[] reqRemainingCapacity = new int[requirements.size()];
        for (int i = 0; i < requirements.size(); i++) {
            reqRemainingCapacity[i] = requirements.get(i).quantity();
        }

        List<String> complexSkuList = new ArrayList<>();
        List<String> unassignedItems = new ArrayList<>();

        for (String sku : skuList) {
            int qty = cartQty.get(sku);
            if (qty <= 0) continue;

            int matchIdx = -1;
            boolean isComplex = false;
            for (int j = 0; j < requirements.size(); j++) {
                if (reqIsWildcard.get(j) || reqAcceptable.get(j).contains(sku)) {
                    if (matchIdx == -1) {
                        matchIdx = j;
                    } else {
                        isComplex = true;
                        break;
                    }
                }
            }

            if (matchIdx != -1 && !isComplex) {
                int assigned = Math.min(qty, reqRemainingCapacity[matchIdx]);
                reqRemainingCapacity[matchIdx] -= assigned;
                int leftover = qty - assigned;
                if (leftover > 0) {
                    unassignedItems.add(sku + " (" + leftover + ")");
                }
            } else {
                complexSkuList.add(sku);
            }
        }

        if (!complexSkuList.isEmpty()) {
            MaxFlowResult result = lineItemsMaxFlow(
                    complexSkuList, cartQty, requirements, reqAcceptable, reqIsWildcard,
                    reqRemainingCapacity, mode);
            int maxF = result.flow;
            List<Map<Integer, Integer>> residual = result.residualGraph;

            int totalComplexCart = 0;
            for (String sku : complexSkuList) {
                totalComplexCart += cartQty.get(sku);
            }

            if (maxF < totalComplexCart) {
                int source = 0;
                int skuOffset = 1;
                for (int i = 0; i < complexSkuList.size(); i++) {
                    int skuNode = skuOffset + i;
                    Integer remaining = residual.get(source).get(skuNode);
                    if (remaining != null && remaining > 0) {
                        unassignedItems.add(complexSkuList.get(i) + " (" + remaining + ")");
                    }
                }
            }
        }

        if (!unassignedItems.isEmpty()) {
            violations.add("Cannot satisfy line item constraints: "
                    + String.join(", ", unassignedItems)
                    + " could not be assigned to any requirement slot");
        }

        return violations;
    }

    private static final class MaxFlowResult {
        final int flow;
        final List<Map<Integer, Integer>> residualGraph;

        MaxFlowResult(int flow, List<Map<Integer, Integer>> residualGraph) {
            this.flow = flow;
            this.residualGraph = residualGraph;
        }
    }

    private static MaxFlowResult lineItemsMaxFlow(
            List<String> skuList,
            Map<String, Integer> cartQty,
            List<LineItemRequirements> requirements,
            List<Set<String>> reqAcceptable,
            List<Boolean> reqIsWildcard,
            int[] reqRemainingCapacity,
            String mode) {

        int sCount = skuList.size();
        int rCount = requirements.size();
        int n = 1 + sCount + rCount + 1;
        int source = 0;
        int sink = n - 1;

        int skuOffset = 1;
        int reqOffset = skuOffset + sCount;

        List<Map<Integer, Integer>> graph = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            graph.add(new HashMap<>());
        }

        for (int i = 0; i < skuList.size(); i++) {
            int u = source;
            int v = skuOffset + i;
            graph.get(u).put(v, cartQty.get(skuList.get(i)));
            graph.get(v).put(u, 0);
        }

        for (int i = 0; i < skuList.size(); i++) {
            String sku = skuList.get(i);
            for (int j = 0; j < requirements.size(); j++) {
                if (reqIsWildcard.get(j) || reqAcceptable.get(j).contains(sku)) {
                    int u = skuOffset + i;
                    int v = reqOffset + j;
                    graph.get(u).put(v, INF);
                    graph.get(v).put(u, 0);
                }
            }
        }

        for (int j = 0; j < requirements.size(); j++) {
            int u = reqOffset + j;
            int v = sink;
            graph.get(u).put(v, reqRemainingCapacity[j]);
            graph.get(v).put(u, 0);
        }

        int flow;
        if ("edmonds_karp".equals(mode)) {
            flow = edmondsKarpSparse(graph, source, sink, n);
        } else {
            flow = dinicSparse(graph, source, sink, n);
        }

        return new MaxFlowResult(flow, graph);
    }

    private static int edmondsKarpSparse(List<Map<Integer, Integer>> graph, int source, int sink, int n) {
        int maxFlow = 0;

        while (true) {
            int[] parent = new int[n];
            for (int i = 0; i < n; i++) parent[i] = -1;
            parent[source] = source;

            Deque<Integer> q = new ArrayDeque<>();
            q.add(source);
            boolean reachedSink = false;

            while (!q.isEmpty() && !reachedSink) {
                int u = q.pollFirst();
                for (Map.Entry<Integer, Integer> entry : graph.get(u).entrySet()) {
                    int v = entry.getKey();
                    int cap = entry.getValue();
                    if (parent[v] == -1 && cap > 0) {
                        parent[v] = u;
                        if (v == sink) {
                            reachedSink = true;
                            break;
                        }
                        q.add(v);
                    }
                }
            }

            if (parent[sink] == -1) break;

            int push = INF;
            int curr = sink;
            while (curr != source) {
                int p = parent[curr];
                push = Math.min(push, graph.get(p).get(curr));
                curr = p;
            }

            maxFlow += push;

            curr = sink;
            while (curr != source) {
                int p = parent[curr];
                graph.get(p).merge(curr, -push, Integer::sum);
                graph.get(curr).merge(p, push, Integer::sum);
                curr = p;
            }
        }

        return maxFlow;
    }

    private static int dinicSparse(List<Map<Integer, Integer>> graph, int source, int sink, int n) {
        List<List<Integer>> adjNodes = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            adjNodes.add(new ArrayList<>(graph.get(i).keySet()));
        }

        int total = 0;
        while (true) {
            int[] level = bfsLevel(graph, source, sink, n, adjNodes);
            if (level == null) break;

            int[] it = new int[n];
            while (true) {
                int f = dfsBlock(graph, source, sink, INF, level, it, adjNodes);
                if (f == 0) break;
                total += f;
            }
        }

        return total;
    }

    private static int[] bfsLevel(List<Map<Integer, Integer>> graph, int source, int sink, int n,
            List<List<Integer>> adjNodes) {
        int[] level = new int[n];
        for (int i = 0; i < n; i++) level[i] = -1;
        level[source] = 0;
        Deque<Integer> q = new ArrayDeque<>();
        q.add(source);
        while (!q.isEmpty()) {
            int u = q.pollFirst();
            for (int v : adjNodes.get(u)) {
                if (level[v] == -1 && graph.get(u).getOrDefault(v, 0) > 0) {
                    level[v] = level[u] + 1;
                    q.add(v);
                }
            }
        }
        return level[sink] != -1 ? level : null;
    }

    private static int dfsBlock(List<Map<Integer, Integer>> graph, int u, int sink, int pushed,
            int[] level, int[] it, List<List<Integer>> adjNodes) {
        if (u == sink || pushed == 0) return pushed;

        int totalPushed = 0;
        List<Integer> adj = adjNodes.get(u);
        while (it[u] < adj.size()) {
            int v = adj.get(it[u]);
            int cap = graph.get(u).getOrDefault(v, 0);

            if (level[v] == level[u] + 1 && cap > 0) {
                int d = dfsBlock(graph, v, sink, Math.min(pushed, cap), level, it, adjNodes);
                if (d > 0) {
                    graph.get(u).merge(v, -d, Integer::sum);
                    graph.get(v).merge(u, d, Integer::sum);
                    totalPushed += d;
                    pushed -= d;
                    if (pushed == 0) break;
                }
            }
            it[u]++;
        }

        return totalPushed;
    }
}
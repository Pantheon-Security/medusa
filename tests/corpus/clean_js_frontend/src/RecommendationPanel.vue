<template>
  <div class="recommendation-panel">
    <input v-model="query" placeholder="Search products..." @keyup.enter="search" />
    <button @click="search">Search</button>

    <ul>
      <li v-for="item in results" :key="item.sku">
        {{ item.sku }} — score {{ item.score.toFixed(2) }}
      </li>
    </ul>
  </div>
</template>

<script setup>
import { ref } from "vue";
import { fetchRecommendations } from "./api";

const query = ref("");
const results = ref([]);

async function search() {
  if (!query.value.trim()) return;
  const data = await fetchRecommendations(query.value);
  results.value = data.results || [];
}
</script>

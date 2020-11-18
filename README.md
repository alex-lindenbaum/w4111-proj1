PostgreSQL account: al4008

URL: http://localhost:8111/

Implemented parts:
We implemented a general user interface for observing the pantry and recieving recommendations based on liked items and dietary restrictions. Authentication/authorization were implemented with SHA256 hashing and sessions. Food items in the pantry may be added and removed. In adding an item, a detailed form allows the user to specify the food, amount, unit, and date bought. The /recipes page shows recommendations for liked recipes, recipes that fulfill the user's dietary restrictions, and other recipes that the user has not liked or disliked yet. Liked recipes can be unliked with a button, and other recipes can either be liked or disliked.

What we changed from our initial design was the layout of the site in general. Originally, the idea was for the user to observe their pantry first, and then be taken to the recommended recipes. Rather, we decided to implement a more horizontal layout, where the pantry and recipes pages are at the same level in the site tree

Schema modifications:
We also improved our schema from part 2. We added check constraints to check that shelf_life is >= 0 in food_items, and to check that amount is > 0 in storage_details.

Database operations:
1. /recipes
When the browser GETS /recipes, among other queries, a query is submitted to Postgres server to retrieve the recipes that (1) the user has at least two ingredients for, and (2) the user has not liked or disliked the recipe. Multiple query results are combined to populate the /recipes page with liked recipes, new recipes that the user has ingredients for, and all recipes that fulfill the user's dietary restrictions.

POST /recipes/like, /recipes/dislike, or /recipes/unlike creates or deletes an impression a user has for the specific recipe.

The interesting part of GET /recipes is that to get the new recipes, the SQL UNION operator is utilized, which is somewhat uncommon but fits perfectly for the application.

2. /shoppinglist
When the browser GETS /shoppinglist, it generates the list of food items which are in the recipes that the user liked. To perform this query, we natural-joined the has_impression and in_recipe relations to get tuples for the recipes in has_impression with each of their ingredients. We then selected those that were liked by the user, and then projected onto food_names
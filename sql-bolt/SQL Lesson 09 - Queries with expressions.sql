-- List all movies and their combined sales in millions of dollars ✓
-- List all movies and their ratings in percent ✓
-- List all movies that were released on even number years ✓

select title, (domestic_sales + international_sales) / 1000000 as combined_sales from movies inner join boxoffice on id = movie_id;
select title, rating * 10 as percent_rating from movies inner join boxoffice on id = movie_id;
select title from movies where year % 2 = 0;

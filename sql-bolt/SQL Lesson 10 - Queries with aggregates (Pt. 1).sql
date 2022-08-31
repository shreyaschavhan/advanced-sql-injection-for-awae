-- Find the longest time that an employee has been at the studio ✓
-- For each role, find the average number of years employed by employees in that role ✓
-- Find the total number of employee years worked in each building ✓

select MAX(years_employed) from employees;
select role, avg(years_employed) from employees group by role;
select building, sum(years_employed) from employees group by building;


-- Find the name and role of all employees who have not been assigned to a building ✓
-- Find the names of the buildings that hold no employees ✓

SELECT name, role FROM employees where building is null;
select building_name from buildings left join employees on building_name = building where building is null;

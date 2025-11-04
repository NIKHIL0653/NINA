import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
  test('should allow user to register', async ({ page }) => {
    await page.goto('/register');

    // Fill registration form
    await page.fill('[name="firstName"]', 'John');
    await page.fill('[name="lastName"]', 'Doe');
    await page.fill('[name="email"]', `john.doe.${Date.now()}@example.com`);
    await page.fill('[name="password"]', 'StrongPass123!');

    // Submit form
    await page.click('button[type="submit"]');

    // Should redirect to chat or show success message
    await expect(page).toHaveURL(/\/chat/);
  });

  test('should allow user to login', async ({ page }) => {
    await page.goto('/login');

    // Fill login form
    await page.fill('[name="email"]', 'test@example.com');
    await page.fill('[name="password"]', 'testpassword');

    // Submit form
    await page.click('button[type="submit"]');

    // Should redirect to chat
    await expect(page).toHaveURL(/\/chat/);
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.goto('/login');

    // Fill with invalid credentials
    await page.fill('[name="email"]', 'invalid@example.com');
    await page.fill('[name="password"]', 'wrongpassword');

    // Submit form
    await page.click('button[type="submit"]');

    // Should show error message
    await expect(page.locator('text=Invalid login credentials')).toBeVisible();
  });
});
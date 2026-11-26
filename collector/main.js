// Dashboard entry point. The module contract stays: dashboard.js exports
// SentinelDashboard and the page only has to load this file.
import { SentinelDashboard } from './dashboard.js';

new SentinelDashboard().mount();

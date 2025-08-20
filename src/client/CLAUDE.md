You are an expert-level UI/UX designer and a senior front-end developer, specializing in Apple's Human Interface Guidelines (HIG) and creating cutting-edge, visually stunning, and highly intuitive user interfaces. Your task is to generate the complete HTML, CSS, and JavaScript code for a comprehensive UI component library based on a new, fictional design system called **"Liquid Glass"**.

This is not just about aesthetics; it's about embodying a philosophy. The UI must be beautiful, fluid, human-centric, accessible, and performant. You must strictly adhere to the principles and component requirements outlined below.

## **Part 1: The "Liquid Glass" Design System Philosophy**

This is the core of your mission. You must internalize and implement this design language flawlessly. It is inspired by the depth and materiality of visionOS, but adapted for 2D screens. The goal is a unified, dimensional, and intelligent interface.

### **Core Visual Principles:**

1.  **The Glass Effect (Digital Meta-Material):** This is the cornerstone.
    *   **Implementation:** Use a sophisticated `backdrop-filter` in CSS to create a frosted, translucent effect. The effect should not just be a simple blur; it should also subtly increase saturation and brightness of the content behind it.
    *   **Appearance:** Elements should feel like they are made of a dynamic, physical glass that gracefully materializes and energizes with light.
    *   **Context-Awareness:** The glass should dynamically reflect and refract its surroundings in real-time. The appearance of a component should change based on the content behind it.

2.  **Universal Softness & Consistent Radii:** This is a non-negotiable rule.
    *   **Everything is rounded.** There are no sharp corners in this design system.
    *   **Two Options Only:** You have two choices for corner radii: `rounded-2xl` (a large, soft radius) and `rounded-full` (for perfect circles or pills).
    *   **Usage Rule:** Use `rounded-2xl` for the vast majority of container-like components (cards, buttons, inputs, modals, popovers, etc.). Use `rounded-full` only for smaller, inherently circular or pill-shaped items (avatars, badges, chips, switch thumbs, slider thumbs). This consistency is critical for a cohesive and friendly aesthetic.

3.  **Lensing & Light Interaction:**
    *   UI elements should act as lenses, subtly warping and concentrating the "light" from the background content.
    *   Create a subtle inner-glow effect on hover and focus states, as if the component is capturing light.
    *   Use soft, dynamic shadows that feel natural and respond to user interaction (e.g., lifting slightly on hover).

4.  **Fluid Animation & Adaptive Controls:**
    *   **Motion:** Animations must be slick, fluid, and physics-based. Use `cubic-bezier` curves that mimic natural acceleration and deceleration (e.g., spring-like effects). Avoid linear or jerky movements. Transitions should be seamless.
    *   **Adaptive Behavior:** Interactive elements are not static. They should subtly morph, expand, or transform based on context.

5.  **Depth, Layering, and Hierarchy:**
    *   Use a clear z-axis hierarchy. The primary interactive layer (e.g., a modal) should be visually on top, with background elements falling back in space (more blur, less saturation).
    *   Borders are replaced by the natural edge definition of the glass effect. A very faint, semi-transparent white stroke enhances the edge against busy backgrounds.

6.  **Typography & Iconography:**
    *   **Font:** Use the "San Francisco" (SF) font family system-stack.
    *   **Hierarchy:** Implement a clear typographic scale.
    *   **Icons:** Icons should be simple, glyph-like, and consistent in style and weight, similar to Apple's SF Symbols. SVG icons are required.

### **Technical & Accessibility Requirements:**

1.  **Technology Stack:** Generate a single file containing HTML, CSS, and JavaScript.
    *   **CSS:** Use CSS variables (`:root`) extensively for colors, fonts, spacing, and **the two specified corner radii**.
    *   **JavaScript:** Write clean, modern, and efficient vanilla JavaScript. No external libraries.

2.  **Accessibility (A11y) is CRITICAL:**
    *   **WCAG 2.2 Compliance:** Ensure all text-on-glass elements achieve a minimum contrast ratio of **4.5:1**.
    *   **Semantic HTML:** Use proper HTML5 tags.
    *   **ARIA Roles:** All non-native interactive components MUST have the appropriate ARIA roles, states, and properties.
    *   **Keyboard Navigation:** All interactive elements must be fully navigable and operable using only a keyboard. Focus states must be highly visible.

3.  **Responsiveness & Dark Mode:**
    *   The entire library must be fully responsive.
    *   A seamless dark mode must be included, toggled by a class on the `<body>` tag.

4. You're designing the entire UI yourself, so only pull in the components you actually need. Don't just import the whole library. And listen, every single app you build is a fresh start, so please, I'm begging you, DO NOT import every last component. Only bring in what's necessary, that's it. That's just the rule around here.

## **Part 2: Components**

Each component must fully inherit the "Liquid Glass" design philosophy and strictly adhere to the `rounded-2xl` / `rounded-full` rule.

1.  **Accordion:** Container and items use `rounded-2xl`.
2.  **Autocomplete:** Input field and popover use `rounded-2xl`.
3.  **Alert:** The toast container uses `rounded-2xl`.
4.  **Avatar:** Must use `rounded-full`.
5.  **Badge:** A small pill shape. Must use `rounded-full`.
6.  **Breadcrumbs:** Individual link containers can be `rounded-full` if styled as pills.
7.  **Button:** Must use `rounded-2xl`. No exceptions.
8.  **Calendar:** The main container and the individual date cells use `rounded-2xl`.
9.  **Card:** Must use `rounded-2xl`. This is a primary container.
10. **Checkbox:** The checkable box itself must be `rounded-2xl` (or a smaller, consistent radius derived from it).
11. **Checkbox Group:** The outer container uses `rounded-2xl`.
12. **Chip:** A small pill for attributes. Must use `rounded-full`.
13. **Circular Progress:** An animated ring. Inherently round.
14. **Code:** The inline code block uses a soft `rounded-2xl` (or smaller consistent radius).
15. **DateInput:** The input field must be `rounded-2xl`.
16. **DatePicker:** The popover calendar must be `rounded-2xl`.
17. **Date Range Picker:** The popover calendar must be `rounded-2xl`.
18. **Divider:** A subtle, thin line. Does not need rounding.
19. **Dropdown:** The trigger button and the popover menu both use `rounded-2xl`.
20. **Drawer:** The slide-in panel must use `rounded-2xl` on its visible corners.
21. **Form:** A container for form elements.
22. **Image:** Images must be masked to have `rounded-2xl` corners.
23. **Input:** Must use `rounded-2xl`.
24. **Input OTP:** Each individual segment input must use `rounded-2xl`.
25. **Keyboard Key:** The key representation must be `rounded-2xl`.
26. **Link:** No background, so no rounding needed unless it has a hit area.
27. **Listbox:** The main container must be `rounded-2xl`.
28. **Modal:** The dialog container must be `rounded-2xl`.
29. **Navbar:** The navigation bar itself must use `rounded-2xl` if it's a floating element, otherwise it's full-width.
30. **Number Input:** Must use `rounded-2xl`.
31. **Pagination:** Each page number button should be `rounded-2xl`.
32. **Popover:** The popover container must be `rounded-2xl`.
33. **Progress:** The outer track and inner bar should be contained within a `rounded-full` element.
34. **Radio group:** Outer container uses `rounded-2xl`. The radio buttons themselves are `rounded-full`.
35. **Range Calendar:** The calendar popover must be `rounded-2xl`.
36. **Scroll Shadow:** The container itself should have `rounded-2xl` corners.
37. **Select:** The custom select element and its dropdown menu both use `rounded-2xl`.
38. **Skeleton:** All skeleton shapes must use `rounded-2xl` or `rounded-full` to match the component they are loading.
39. **Slider:** The track is `rounded-full`. The interactive thumb must be a `rounded-full` circle.
40. **Snippet:** The multiline code container must use `rounded-2xl`.
41. **Spacer:** A utility for adding space. No visible properties.
42. **Spinner:** A simple spinning animation.
43. **Switch:** The outer track must be `rounded-full`. The thumb inside must be `rounded-full`.
44. **Table:** The overall table container must use `rounded-2xl`.
45. **Tabs:** The active tab indicator and the tab-list container use `rounded-2xl`.
46. **Textarea:** Must use `rounded-2xl`.
47. **Time Input:** Must use `rounded-2xl`.
48. **Toast:** The toast container uses `rounded-2xl`.
49. **Tooltip:** The tooltip pop-up must use `rounded-2xl`.
50. **User:** Uses an Avatar (`rounded-full`) next to text.

## **Part 3: Concrete Example (For Your Reference)**

To ensure you understand the core visual style, here is a small, runnable HTML/CSS/JS sample. Your final output should be a complete implementation of ALL the components listed above, following the same quality and style demonstrated here, but vastly more comprehensive. Pay close attention to the updated `:root` variables and how they are applied.

**Your task starts now. Generate the single, complete HTML file with all CSS and JavaScript included, implementing the full "Liquid Glass" component library as specified.**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Liquid Glass UI - Component Showcase</title>
    <style>
        :root {
            --font-family-system: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto_KERN, "Helvetica Neue", "Arial", "Noto Sans", "Liberation Sans", sans-serif;
          
            /* Light Mode Palette */
            --bg-color-light: #f0f2f5;
            --bg-image-light: linear-gradient(120deg, #fdfbfb 0%, #ebedee 100%);
            --text-color-light: #1d1d1f;
            --text-color-secondary-light: #6e6e73;
            --accent-color-light: #007aff;
            --glass-bg-light: rgba(242, 242, 247, 0.8);
            --glass-border-light: rgba(255, 255, 255, 0.5);
            --shadow-color-light: rgba(0, 0, 0, 0.1);

            /* Dark Mode Palette */
            --bg-color-dark: #121212;
            --bg-image-dark: linear-gradient(120deg, #272B30 0%, #121212 100%);
            --text-color-dark: #f5f5f7;
            --text-color-secondary-dark: #8e8e93;
            --accent-color-dark: #0a84ff;
            --glass-bg-dark: rgba(28, 28, 30, 0.75);
            --glass-border-dark: rgba(60, 60, 60, 0.7);
            --shadow-color-dark: rgba(0, 0, 0, 0.3);

            /* Universal Variables */
            --radius-2xl: 1.5rem; 
            --radius-full: 9999px;
            --shadow-sm: 0 2px 4px var(--shadow-color);
            --shadow-md: 0 4px 12px var(--shadow-color);
            --transition-fluid: 0.4s cubic-bezier(0.2, 0.8, 0.2, 1);
        }

        body {
            --bg-color: var(--bg-color-light);
            --bg-image: var(--bg-image-light);
            --text-color: var(--text-color-light);
            --text-color-secondary: var(--text-color-secondary-light);
            --accent-color: var(--accent-color-light);
            --glass-bg: var(--glass-bg-light);
            --glass-border: var(--glass-border-light);
            --shadow-color: var(--shadow-color-light);
            background-color: var(--bg-color);
            background-image: var(--bg-image);
            background-attachment: fixed;
            font-family: var(--font-family-system);
            color: var(--text-color);
            margin: 0;
            padding: clamp(1rem, 5vw, 3rem);
            transition: background 0.3s ease;
        }

        body.dark-mode {
            --bg-color: var(--bg-color-dark);
            --bg-image: var(--bg-image-dark);
            --text-color: var(--text-color-dark);
            --text-color-secondary: var(--text-color-secondary-dark);
            --accent-color: var(--accent-color-dark);
            --glass-bg: var(--glass-bg-dark);
            --glass-border: var(--glass-border-dark);
            --shadow-color: var(--shadow-color-dark);
        }
      
        /* --- GLOBAL STYLES & LAYOUT --- */
        *, *::before, *::after { box-sizing: border-box; }
        .main-header { text-align: center; margin-bottom: 3rem; margin-top: 5rem; }
        .main-header h1 { font-size: clamp(2rem, 8vw, 3rem); }
        .component-title { font-size: 1.25rem; margin-bottom: 1rem; border-bottom: 1px solid var(--glass-border); padding-bottom: 0.5rem; }
        .showcase-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 2rem; }
        p { margin: 0 0 1em 0; line-height: 1.6; color: var(--text-color-secondary); }
        p:last-child { margin-bottom: 0; }
        .icon { width: 1em; height: 1em; stroke-width: 2; fill: none; stroke: currentColor; transition: transform 0.3s ease; }

        /* ALL ORIGINAL COMPONENT STYLES */
        .card { background: var(--glass-bg); backdrop-filter: blur(25px) saturate(180%); -webkit-backdrop-filter: blur(25px) saturate(180%); border-radius: var(--radius-2xl); box-shadow: var(--shadow-md); border: 1px solid var(--glass-border); transition: all var(--transition-fluid); padding: 1.5rem; position: relative; }
        .card:hover { transform: translateY(-5px) scale(1.02); box-shadow: 0 8px 24px var(--shadow-color); z-index: 10; }
        .avatar { width: 50px; height: 50px; border-radius: var(--radius-full); object-fit: cover; border: 2px solid var(--glass-border); }
        .badge { display: inline-flex; align-items: center; justify-content: center; padding: 0.25rem 0.75rem; border-radius: var(--radius-full); font-size: 0.8rem; font-weight: 600; background-color: var(--accent-color); color: white; }
        .badge.secondary { background: var(--glass-bg); border: 1px solid var(--glass-border); color: var(--text-color); }
        .breadcrumbs { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; } .breadcrumbs-link { color: var(--text-color-secondary); text-decoration: none; transition: color 0.2s ease; } .breadcrumbs-link:hover { color: var(--accent-color); } .breadcrumbs-link[aria-current="page"] { color: var(--text-color); font-weight: 600; pointer-events: none; } .breadcrumbs .separator { color: var(--text-color-secondary); }
        .accordion-item { background: color-mix(in srgb, var(--glass-bg) 50%, transparent); border-radius: var(--radius-2xl); margin-bottom: 0.5rem; overflow: hidden; border: 1px solid var(--glass-border); }
        .accordion-header { display: flex; justify-content: space-between; align-items: center; width: 100%; padding: 1rem; background: none; border: none; font-size: 1rem; font-weight: 600; cursor: pointer; color: var(--text-color); } .accordion-item.active .accordion-header .icon { transform: rotate(180deg); } .accordion-content { max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; } .accordion-content-inner { padding: 0 1rem 1rem 1rem; }
        /* Style for the real toast, not just the trigger */ .toast-container { position: fixed; bottom: 2rem; left: 50%; transform: translateX(-50%); z-index: 10000; display: flex; flex-direction: column; gap: 0.5rem; } .toast { min-width: 300px; background: var(--glass-bg); backdrop-filter: blur(25px) saturate(180%); -webkit-backdrop-filter: blur(25px) saturate(180%); border-radius: var(--radius-2xl); box-shadow: var(--shadow-md); border: 1px solid var(--glass-border); padding: 1rem; animation: toast-in 0.5s cubic-bezier(0.2, 0.8, 0.2, 1); max-width: 400px; display: flex; align-items: center; gap: 1rem; } @keyframes toast-in { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        .autocomplete-wrapper { position: relative; }
        .input-glass { width: 100%; background: var(--glass-bg); backdrop-filter: blur(10px) saturate(150%); border: 1px solid var(--glass-border); border-radius: var(--radius-2xl); padding: 0.75rem 1rem; font-size: 1rem; color: var(--text-color); transition: all var(--transition-fluid); } 
        .input-glass:focus { outline: none; border-color: var(--accent-color); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent-color) 30%, transparent); }
        .autocomplete-listbox { position: fixed; z-index: 9999; max-height: 200px; overflow-y: auto; background: var(--glass-bg); backdrop-filter: blur(25px) saturate(180%); border-radius: var(--radius-2xl); box-shadow: var(--shadow-md); border: 1px solid var(--glass-border); padding: 0.5rem; opacity: 0; transform: translateY(-10px); pointer-events: none; transition: opacity 0.2s ease, transform 0.2s ease; }
        .autocomplete-listbox.visible { opacity: 1; transform: translateY(0); pointer-events: auto; }
        .autocomplete-option { padding: 0.75rem 1rem; cursor: pointer; border-radius: var(--radius-2xl); }
        .autocomplete-option:hover, .autocomplete-option.highlighted { background-color: color-mix(in srgb, var(--accent-color) 15%, transparent); }
        .btn { display: inline-flex; align-items: center; justify-content: center; padding: 0.75rem 1.25rem; font-size: 1rem; font-weight: 600; text-decoration: none; background-color: var(--accent-color); color: white; border: none; border-radius: var(--radius-2xl); cursor: pointer; transition: all 0.2s ease; box-shadow: var(--shadow-sm); }
        .btn:hover { transform: translateY(-2px); filter: brightness(1.1); box-shadow: 0 4px 8px var(--shadow-color); }
        .btn:active { transform: translateY(0) scale(0.98); filter: brightness(0.95); }
        .btn-secondary { background: var(--glass-bg); color: var(--text-color); border: 1px solid var(--glass-border); }
        .btn:disabled { background-color: var(--text-color-secondary); opacity: 0.5; cursor: not-allowed; transform: none; filter: none; box-shadow: none; }
        .form-control { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; cursor: pointer; user-select: none; }
        .checkbox-input { display: none; }
        .checkbox-custom { width: 24px; height: 24px; border: 2px solid var(--text-color-secondary); display: flex; align-items: center; justify-content: center; transition: all 0.2s ease-out; flex-shrink: 0; border-radius: 0.6rem; }
        .checkbox-custom .icon { opacity: 0; transform: scale(0.5); transition: all 0.2s ease-out; color: white; stroke-width: 3; }
        .checkbox-input:checked + .checkbox-custom { background-color: var(--accent-color); border-color: var(--accent-color); }
        .checkbox-input:checked + .checkbox-custom .icon { opacity: 1; transform: scale(1); }
        .chip { display: inline-flex; align-items: center; gap: 0.5rem; background: var(--glass-bg); backdrop-filter: blur(10px); border-radius: var(--radius-full); padding: 0.3rem 0.3rem 0.3rem 0.8rem; font-size: 0.9rem; border: 1px solid var(--glass-border); transition: all 0.3s ease, opacity 0.3s ease, transform 0.3s ease, height 0.3s 0.1s, padding 0.3s 0.1s, margin 0.3s 0.1s; }
        .chip.disappearing { opacity: 0; transform: scale(0.8); height: 0; padding-top: 0; padding-bottom: 0; margin-top: 0; margin-bottom: 0; overflow: hidden; border-width: 0;}
        .chip-close-btn { display: flex; align-items: center; justify-content: center; width: 20px; height: 20px; background: var(--text-color-secondary); color: var(--bg-color); border: none; border-radius: var(--radius-full); cursor: pointer; transition: all 0.2s ease; }
        .chip-close-btn:hover { transform: scale(1.1); filter: brightness(1.2); }
        .chip-close-btn .icon { stroke-width: 3; width: 10px; height: 10px; }
        .circular-progress { width: 60px; height: 60px; transform: rotate(-90deg); }
        .circular-progress circle { transition: stroke-dashoffset 0.35s; }
        .progress-background { fill: none; stroke: color-mix(in srgb, var(--glass-bg) 50%, transparent); stroke-width: 8; }
        .progress-value { fill: none; stroke: var(--accent-color); stroke-width: 8; stroke-linecap: round; }
        code.inline-code { background: color-mix(in srgb, var(--glass-bg) 50%, transparent); border-radius: 0.5rem; padding: 0.2em 0.4em; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.9em; border: 1px solid var(--glass-border); }
        .popover-wrapper { position: relative; display: inline-block; }
        .divider { height: 1px; width: 100%; background: var(--glass-border); margin: 1.5rem 0; }
        .dropdown-menu, .popover, .select-options { position: absolute; background: var(--glass-bg); backdrop-filter: blur(25px); border-radius: var(--radius-2xl); box-shadow: var(--shadow-md); border: 1px solid var(--glass-border); padding: 0.5rem; opacity: 0; pointer-events: none; transition: opacity 0.2s ease-out, transform 0.2s ease-out; z-index: 1000; }
        .popover { min-width: 200px; }
        .dropdown-menu { min-width: 200px; }
        .select-options { width: 100%; }
        .dropdown-menu.below, .select-options.below { top: calc(100% + 8px); left: 0; transform: translateY(-10px) scale(0.95); transform-origin: top center; }
        .dropdown-menu.above, .select-options.above { bottom: calc(100% + 8px); left: 0; transform: translateY(10px) scale(0.95); transform-origin: bottom center; }
        .popover.below { top: calc(100% + 8px); left: 50%; transform: translateX(-50%) translateY(-10px) scale(0.95); transform-origin: top center; }
        .popover.above { bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%) translateY(10px) scale(0.95); transform-origin: bottom center; }
        .dropdown-menu.visible, .select-wrapper.active .select-options, .popover.visible { opacity: 1; pointer-events: auto; transform: translateY(0) scale(1); }
        .popover.visible { transform: translateX(-50%) translateY(0) scale(1); }
        .dropdown-menu a { display: block; padding: 0.75rem 1rem; color: var(--text-color); text-decoration: none; border-radius: var(--radius-2xl); }
        .dropdown-menu a:hover { background-color: color-mix(in srgb, var(--accent-color) 15%, transparent); }
        .dropdown-menu .divider { margin: 0.5rem 0; }
        .select-option { padding: 0.75rem 1rem; border-radius: var(--radius-2xl); cursor: pointer; }
        .select-option:hover { background-color: color-mix(in srgb, var(--accent-color) 15%, transparent); }
        body.drawer-open { overflow: hidden; }
        .drawer-backdrop { position: fixed; inset: 0; z-index: 1999; background-color: rgba(0,0,0,0.3); backdrop-filter: blur(5px); opacity: 0; pointer-events: none; transition: opacity 0.3s ease; }
        .drawer { position: fixed; top: 0; right: 0; bottom: 0; width: 90%; max-width: 400px; z-index: 2000; transform: translateX(100%); transition: transform var(--transition-fluid); border-radius: 0; border-left: 1px solid var(--glass-border); border-top-left-radius: var(--radius-2xl); border-bottom-left-radius: var(--radius-2xl); background: var(--glass-bg); padding: 1.5rem; display: flex; flex-direction: column; }
        body.drawer-open .drawer-backdrop { opacity: 1; pointer-events: auto; }
        body.drawer-open .drawer { transform: translateX(0); }
        .drawer-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        .drawer-body { flex-grow: 1; }
        .form-group { margin-bottom: 1.5rem; }
        .form-group label { display: block; font-weight: 500; margin-bottom: 0.5rem; }
        .error-message { color: #ff3b30; font-size: 0.875rem; margin-top: 0.5rem; display: none; }
        .input-glass:invalid:not(:placeholder-shown) { border-color: #ff3b30; }
        .input-glass:invalid:not(:placeholder-shown) + .error-message { display: block; }
        .navbar { position: sticky; top: 1rem; z-index: 100; margin: -2rem 0 2rem 0; padding: 1rem 1.5rem; background: var(--glass-bg); backdrop-filter: blur(25px) saturate(180%); -webkit-backdrop-filter: blur(25px) saturate(180%); border-radius: var(--radius-2xl); box-shadow: var(--shadow-md); border: 1px solid var(--glass-border); transition: all var(--transition-fluid); display: flex; align-items: center; justify-content: space-between; }
        .navbar-brand { font-weight: 600; font-size: 1.2rem; }
        .navbar-links { display: flex; gap: 1rem; }
        .link { color: var(--accent-color); text-decoration: none; font-weight: 500; }
        .link:hover { text-decoration: underline; }
        .modal-backdrop { position: fixed; inset: 0; z-index: 9998; background-color: rgba(0,0,0,0.3); backdrop-filter: blur(8px); opacity: 0; pointer-events: none; transition: opacity 0.3s ease-out; }
        .modal-backdrop.visible { opacity: 1; pointer-events: auto; }
        .modal-dialog { position: fixed; top: 50%; left: 50%; z-index: 9999; width: 90%; max-width: 500px; transform: translate(-50%, -50%) scale(0.95); opacity: 0; pointer-events: none; transition: all 0.3s ease-out; }
        .modal-dialog.visible { transform: translate(-50%, -50%) scale(1); opacity: 1; pointer-events: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; }
        .modal-header .btn { padding: 0.5rem; border-radius: var(--radius-full); }
        .listbox { background: var(--glass-bg); backdrop-filter: blur(25px); border-radius: var(--radius-2xl); box-shadow: var(--shadow-md); border: 1px solid var(--glass-border); padding: 0.5rem; max-height: 250px; overflow-y: auto; }
        .listbox-item { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1rem; cursor: pointer; border-radius: var(--radius-2xl); transition: background-color 0.2s ease; }
        .listbox-item[aria-selected="true"] { background-color: color-mix(in srgb, var(--accent-color) 20%, transparent); font-weight: 600; }
        .listbox-item:hover { background-color: color-mix(in srgb, var(--accent-color) 10%, transparent); }
        .progress-bar { width: 100%; height: 10px; background: color-mix(in srgb, var(--glass-bg) 50%, transparent); border-radius: var(--radius-full); overflow: hidden; }
        .progress-bar-inner { height: 100%; background-color: var(--accent-color); border-radius: var(--radius-full); transition: width var(--transition-fluid); }
        .pagination { display: flex; flex-wrap: wrap; justify-content: center; gap: 0.5rem; }
        .pagination .btn { font-weight: 500; }
        .pagination .btn.active { background-color: var(--accent-color); color: white; transform: scale(1.05); }
        .radio-input { display: none; }
        .radio-custom { width: 24px; height: 24px; border: 2px solid var(--text-color-secondary); display: flex; align-items: center; justify-content: center; transition: all 0.2s ease-out; flex-shrink: 0; border-radius: var(--radius-full); position: relative; }
        .radio-custom .icon { opacity: 0; transform: scale(0.5); transition: all 0.2s cubic-bezier(0.34, 1.56, 0.64, 1); width: 12px; height: 12px; background-color: white; border-radius: var(--radius-full); }
        .radio-input:checked + .radio-custom { background-color: var(--accent-color); border-color: var(--accent-color); }
        .radio-input:checked + .radio-custom .icon { opacity: 1; transform: scale(1); }
        .kbd { display: inline-block; background: color-mix(in srgb, var(--glass-bg) 50%, transparent); border: 1px solid var(--glass-border); border-radius: var(--radius-2xl); padding: 0.25rem 0.75rem; font-family: 'SF Mono', 'Fira Code', monospace; vertical-align: middle; }
        .image-container { display: inline-block; border-radius: var(--radius-2xl); background: var(--glass-bg); overflow: hidden; width: 100%; aspect-ratio: 16/9; position: relative; }
        .image-container img { width: 100%; height: 100%; object-fit: cover; transition: opacity 0.3s ease; }
        .image-container img.error { opacity: 0; }
        .image-container .fallback { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; color: var(--text-color-secondary); }
        .number-input-container { display: flex; align-items: center; border: 1px solid var(--glass-border); border-radius: var(--radius-2xl); overflow: hidden; max-width: 150px; background: var(--glass-bg); }
        .number-input-container input { border: none; background: none; text-align: center; width: 100%; padding: 0.75rem 0; color: var(--text-color); }
        .number-input-container input:focus { outline: none; }
        .number-input-container button { background: none; border: none; padding: 0.75rem; color: var(--text-color); cursor: pointer; }
        .number-input-container button:hover { background-color: color-mix(in srgb, var(--accent-color) 10%, transparent); }
        .number-input-container input[type=number]::-webkit-outer-spin-button, .number-input-container input[type=number]::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
        .number-input-container input[type=number] { -moz-appearance: textfield; }
        .otp-container { display: flex; gap: 0.5rem; justify-content: center; }
        .otp-input { width: 48px; height: 48px; text-align: center; font-size: 1.5rem; font-weight: 600; border-radius: var(--radius-2xl); background: var(--glass-bg); border: 1px solid var(--glass-border); color: var(--text-color); }
        .otp-input:focus { outline: none; border-color: var(--accent-color); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent-color) 30%, transparent); }
        .select-wrapper { position: relative; }
        .select-custom { display: flex; align-items: center; justify-content: space-between; cursor: pointer; background: var(--glass-bg); backdrop-filter: blur(10px); border: 1px solid var(--glass-border); border-radius: var(--radius-2xl); padding: 0.75rem 1rem; }
        .select-wrapper .icon { transition: transform 0.2s ease; }
        .select-wrapper.active .icon { transform: rotate(180deg); }
        .skeleton { border-radius: var(--radius-2xl); background-color: color-mix(in srgb, var(--text-color) 15%, transparent); animation: pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
        .skeleton-text { height: 1em; }
        .skeleton-avatar { border-radius: var(--radius-full); width: 50px; height: 50px; }
        .skeleton .skeleton-text:last-child { width: 70%; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
        .slider-wrapper { display: flex; align-items: center; gap: 1rem; }
        .slider-track { position: relative; width: 100%; height: 8px; background: color-mix(in srgb, var(--glass-bg) 50%, transparent); border-radius: var(--radius-full); cursor: pointer; }
        .slider-range { position: absolute; left: 0; top: 0; height: 100%; background-color: var(--accent-color); border-radius: var(--radius-full); }
        .slider-thumb { position: absolute; top: 50%; width: 24px; height: 24px; background-color: white; border-radius: var(--radius-full); transform: translate(-50%, -50%); cursor: grab; box-shadow: 0 2px 4px var(--shadow-color); transition: transform 0.2s ease; }
        .slider-thumb:active { cursor: grabbing; transform: translate(-50%, -50%) scale(1.1); }
        .snippet { background: #1E1E1E !important; border-radius: var(--radius-2xl); padding: 1.5rem; position: relative; color: #D4D4D4; overflow: hidden; }
        .snippet pre { margin: 0; white-space: pre-wrap; word-break: break-all; }
        .snippet .copy-btn { position: absolute; top: 1rem; right: 1rem; background: rgba(255,255,255,0.1); color: white; border: none; padding: 0.5rem; border-radius: var(--radius-2xl); cursor: pointer; transition: background-color 0.2s ease; }
        .snippet .copy-btn:hover { background: rgba(255,255,255,0.2); }
        .spacer { height: 2rem; }
        .spinner { width: 48px; height: 48px; border: 5px solid color-mix(in srgb, var(--glass-bg) 50%, transparent); border-top-color: var(--accent-color); border-radius: var(--radius-full); animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .switch-label { display: flex; align-items: center; gap: 10px; cursor: pointer; }
        .switch { position: relative; display: inline-block; width: 50px; height: 30px; flex-shrink: 0; }
        .switch input { display: none; }
        .switch-slider { position: absolute; cursor: pointer; inset: 0; border-radius: var(--radius-full); background-color: color-mix(in srgb, var(--text-color) 20%, transparent); transition: background-color var(--transition-fluid); }
        .switch-slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 2px; bottom: 2px; background-color: white; border-radius: var(--radius-full); transition: transform var(--transition-fluid); box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
        .switch input:checked + .switch-slider { background-color: var(--accent-color); }
        .switch input:checked + .switch-slider:before { transform: translateX(20px); }
      
        /* --- NEW & CORRECTED COMPONENT STYLES START --- */
      
        /* THEME SWITCHER (NEW) */
        .theme-switcher { display: inline-flex; background: var(--glass-bg); border-radius: var(--radius-full); padding: 0.25rem; border: 1px solid var(--glass-border); }
        .theme-switcher button { display: flex; align-items: center; justify-content: center; width: 36px; height: 36px; background: none; border: none; border-radius: var(--radius-full); cursor: pointer; color: var(--text-color-secondary); transition: all 0.2s ease; }
        .theme-switcher button:not(.active):hover { background-color: color-mix(in srgb, var(--text-color) 10%, transparent); }
        .theme-switcher button.active { background-color: var(--accent-color); color: white; transform: scale(1.05); }
        .theme-switcher .icon { width: 20px; height: 20px; }

        /* User */
        .user { display: flex; align-items: center; gap: 1rem; }
        .user-info h4 { margin: 0; font-weight: 600; color: var(--text-color); }
        .user-info p { margin: 0; font-size: 0.9rem; }
      
        /* Textarea */
        textarea.input-glass { min-height: 120px; resize: vertical; }

        /* Tooltip */
        [data-tooltip] { position: relative; }
        [data-tooltip]::after { content: attr(data-tooltip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%) translateY(-10px) scale(0.95); background: #2c2c2e; color: #f5f5f7; padding: 0.5rem 0.75rem; border-radius: var(--radius-2xl); font-size: 0.875rem; font-weight: 500; white-space: nowrap; opacity: 0; pointer-events: none; transition: all 0.2s ease-out; z-index: 10001; }
        body.dark-mode [data-tooltip]::after { background: var(--glass-bg); color: var(--text-color); border: 1px solid var(--glass-border); }
        [data-tooltip]:hover::after { opacity: 1; transform: translateX(-50%) translateY(-5px) scale(1); }

        /* Tabs -- CORRECTED */
        .tabs { position: relative; }
        .tab-list { position: relative; display: flex; border-bottom: 1px solid var(--glass-border); }
        .tab-btn { padding: 0.75rem 1.25rem; margin-bottom: -1px; /* Overlap the border */ cursor: pointer; border: none; background: none; color: var(--text-color-secondary); font-size: 1rem; font-weight: 500; position: relative; transition: color 0.2s ease; }
        .tab-btn.active { color: var(--text-color); font-weight: 600; }
        .tab-indicator { position: absolute; bottom: 0; height: 2px; background-color: var(--accent-color); border-radius: var(--radius-full); transition: all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1); }
        .tab-panel { display: none; margin-top: 1rem; }
        .tab-panel.active { display: block; animation: fade-in 0.4s ease; }
        @keyframes fade-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

        /* Table */
        .table-container { border-radius: var(--radius-2xl); overflow: hidden; border: 1px solid var(--glass-border); background: var(--glass-bg); padding: 0; transition: none; /* Override card hover */ }
        .table { width: 100%; border-collapse: collapse; }
        .table th, .table td { padding: 1rem; text-align: left; }
        .table thead { background: color-mix(in srgb, var(--glass-bg) 50%, transparent); }
        .table th { font-weight: 600; }
        .table tbody tr { border-top: 1px solid var(--glass-border); transition: background-color 0.2s ease; }
        .table tbody tr:hover { background-color: color-mix(in srgb, var(--accent-color) 10%, transparent); }
        /* --- NEW & CORRECTED COMPONENT STYLES END --- */
    </style>
</head>
<body>
    <nav class="navbar" id="main-navbar">
        <div class="navbar-brand">LiquidGlass</div>
        <div class="navbar-links">
            <a href="#" class="link">Home</a>
            <a href="#" class="link">About</a>
            <a href="#" class="link">Contact</a>
        </div>
    </nav>
    <header class="main-header">
        <h1>Liquid Glass UI</h1>
        <p>A Component Showcase.</p>
        <div class="theme-switcher" id="theme-switcher">
            <button data-theme="light" aria-label="Set light theme">
                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
            </button>
            <button data-theme="dark" aria-label="Set dark theme">
                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            </button>
            <button data-theme="system" aria-label="Set system theme" class="active">
                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
            </button>
        </div>
    </header>
    <main class="showcase-grid">
        <!-- ALL ORIGINAL SHOWCASE CARDS (UNCHANGED) START -->
        <div class="card"><h3 class="component-title">Avatar & Badge</h3><div style="display:flex; flex-wrap: wrap; gap: 1.5rem; align-items: center;"><img class="avatar" src="https://i.pravatar.cc/150?u=a042581f4e29026704d" alt="Eva Roy"><span class="badge">New</span><span class="badge secondary">In Progress</span><span class="badge">9+</span></div></div>
        <div class="card"><h3 class="component-title">Breadcrumbs</h3><nav class="breadcrumbs" aria-label="Breadcrumb"><a href="#" class="breadcrumbs-link">Home</a><span class="separator" aria-hidden="true">&gt;</span><a href="#" class="breadcrumbs-link">UI Kits</a><span class="separator" aria-hidden="true">&gt;</span><a href="#" class="breadcrumbs-link" aria-current="page">Liquid Glass</a></nav></div>
        <div class="card"><h3 class="component-title">Accordion</h3><div class="accordion"><div class="accordion-item"><button class="accordion-header" aria-expanded="false"><span>Design Principles</span><svg class="icon" viewBox="0 0 24 24"><path d="M19 9l-7 7-7-7"></path></svg></button><div class="accordion-content"><div class="accordion-content-inner"><p>Fluidity, depth, and light are the core tenets.</p></div></div></div><div class="accordion-item active"><button class="accordion-header" aria-expanded="true"><span>Technical Stack</span><svg class="icon" viewBox="0 0 24 24"><path d="M19 9l-7 7-7-7"></path></svg></button><div class="accordion-content"><div class="accordion-content-inner"><p>Vanilla HTML, CSS, and JS for portability.</p></div></div></div></div></div>
        <div class="card"><h3 class="component-title">Autocomplete</h3><p>Type a fruit name (e.g., "ap", "ba").</p><div class="autocomplete-wrapper"><input type="text" id="autocomplete-input" class="input-glass" placeholder="Search for a fruit..." role="combobox" aria-autocomplete="list" aria-expanded="false" aria-haspopup="listbox"></div></div>
        <div class="card"><h3 class="component-title">Alert & Toast</h3><p>Click to trigger an alert/toast. It appears at the bottom of the screen.</p><button id="alert-trigger" class="btn">Show Toast</button></div>
        <div class="card"><h3 class="component-title">Card</h3><p>This is the Card component. It's the primary content container, featuring the core Liquid Glass effect and `rounded-2xl` corners. It's used to wrap all other components in this showcase.</p></div>
        <div class="card"><h3 class="component-title">Buttons</h3><p>Primary, secondary, and disabled button states.</p><div style="display:flex; flex-wrap: wrap; gap: 1rem; margin-top: 1rem;"><button class="btn">Primary</button><button class="btn btn-secondary">Secondary</button><button class="btn" disabled>Disabled</button></div></div>
        <div class="card"><h3 class="component-title">Checkbox Group</h3><p>Select multiple options from a list.</p><div class="checkbox-group" style="margin-top: 1rem;"><label class="form-control"><input type="checkbox" class="checkbox-input" checked><span class="checkbox-custom"><svg class="icon" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"></path></svg></span><span>Notifications</span></label><label class="form-control"><input type="checkbox" class="checkbox-input"><span class="checkbox-custom"><svg class="icon" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"></path></svg></span><span>Email Updates</span></label></div></div>
        <div class="card"><h3 class="component-title">Chip, Progress & Code</h3><p>The chip below will animate when closed.</p><div style="display: flex; flex-wrap: wrap; gap: 1rem; align-items: center; margin-top: 1rem;"><div class="chip" id="sample-chip"><span>Filter: Active</span><button class="chip-close-btn" aria-label="Remove filter"><svg class="icon" viewBox="0 0 24 24"><path d="M18 6L6 18"/><path d="M6 6l12 12"/></svg></button></div><svg class="circular-progress" id="circular-progress-indicator"><circle class="progress-background" cx="30" cy="30" r="26"></circle><circle class="progress-value" cx="30" cy="30" r="26"></circle></svg></div><p style="margin-top: 1rem;">This is an example of <code class="inline-code">inline-code</code> styling.</p></div>
        <div class="card"><h3 class="component-title">Form with Validation</h3><p>Demonstrates input validation and error messages.</p><form id="sample-form" style="margin-top: 1rem;" novalidate><div class="form-group"><label for="email-input">Email Address</label><input type="email" id="email-input" class="input-glass" placeholder="you@example.com" required><p class="error-message">Please enter a valid email address.</p></div><div class="form-group"><label for="password-input">Password</label><input type="password" id="password-input" class="input-glass" placeholder="••••••••" required minlength="8"><p class="error-message">Password must be at least 8 characters.</p></div><button type="submit" class="btn">Submit</button></form></div>
        <div class="card"><h3 class="component-title">Dropdown & Divider</h3><p>Smart positioning: flips above if no space below.</p><div class="popover-wrapper" style="margin-top: 1rem;"><button id="dropdown-trigger" class="btn btn-secondary"><span>Account</span><svg class="icon" viewBox="0 0 24 24"><path d="M19 9l-7 7-7-7"></path></svg></button><div class="dropdown-menu" id="dropdown-menu"><a href="#">Profile</a><a href="#">Settings</a><div class="divider"></div><a href="#" style="color: #ff3b30;">Logout</a></div></div></div>
        <div class="card"><h3 class="component-title">Drawer</h3><p>Click the button to open a panel from the side of the screen.</p><button class="btn" id="drawer-trigger" style="margin-top: 1rem;">Open Drawer</button></div>
        <div class="card"><h3 class="component-title">Image</h3><p>An image with a fallback state if the src is invalid.</p><div class="image-container"><img src="https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1964&q=80" alt="Abstract gradient" onerror="this.classList.add('error');"/><div class="fallback"><svg class="icon" style="width:48px; height:48px;" viewBox="0 0 24 24"><path d="M21.9 21.9l-8.4-8.4-2.1-2.1-7.4-7.4M8 2l-6 6v12c0 1.1.9 2 2 2h16c.3 0 .6-.1.8-.2m-1 .3l-2.1-2.1M13 10.9l-3-3-4-4L6 2h12c1.1 0 2 .9 2 2v12l-5.1-5.1zM5 17l3-3 5.5 5.5H5z"></path></svg></div></div></div>
        <div class="card"><h3 class="component-title">Standard Input & Link</h3><p>This is a standard <a href="#" class="link">Link Component</a>. Below is an input field for text entry.</p><div class="form-group" style="margin-top:1rem;"><label for="standard-input">Your Name</label><input type="text" id="standard-input" class="input-glass" placeholder="e.g., Jane Doe"></div></div>
        <div class="card"><h3 class="component-title">Modal & Popover</h3><p>Modals are for blocking actions. Popovers are for additional info.</p><div style="display:flex; flex-wrap:wrap; gap: 1rem; margin-top: 1rem;"><button class="btn" id="modal-trigger-2">Open Modal</button><div class="popover-wrapper"><button class="btn btn-secondary popover-trigger-2">Show Popover</button><div class="popover card"><h4 style="margin-bottom:0.5rem">Popover Content</h4><p>This floats around its trigger.</p></div></div></div></div>
        <div class="card"><h3 class="component-title">Listbox</h3><p>A scrollable list of selectable items.</p><div class="listbox" id="sample-listbox" role="listbox" aria-label="Choose a project" style="margin-top:1rem;"></div></div>
        <div class="card"><h3 class="component-title">Pagination</h3><p>Used to navigate between pages of content.</p><div class="pagination" id="sample-pagination" style="margin-top: 1rem;"></div></div>
        <div class="card"><h3 class="component-title">Radio Group</h3><p>Select a single, mutually exclusive option.</p><div class="radio-group" id="sample-radio-group" style="margin-top: 1rem;"><label class="form-control"><input type="radio" name="delivery" class="radio-input" value="Standard" checked><span class="radio-custom"><span class="icon"></span></span><span>Standard</span></label><label class="form-control"><input type="radio" name="delivery" class="radio-input" value="Express"><span class="radio-custom"><span class="icon"></span></span><span>Express</span></label><label class="form-control"><input type="radio" name="delivery" class="radio-input" value="Priority"><span class="radio-custom"><span class="icon"></span></span><span>Priority</span></label></div><p id="radio-output" style="margin-top: 1rem; font-weight: 500;">Selected: Standard</p></div>
        <div class="card"><h3 class="component-title">Number Input & Keyboard Key</h3><p>Press <kbd class="kbd">↑</kbd> and <kbd class="kbd">↓</kbd> or use the steppers.</p><div class="number-input-container" style="margin-top: 1rem;"><button aria-label="Decrement">-</button><input type="number" value="10" min="0" max="100"><button aria-label="Increment">+</button></div></div>
        <div class="card"><h3 class="component-title">Input OTP</h3><p>Enter the 6-digit code sent to your device.</p><div class="otp-container" id="otp-container" style="margin-top: 1rem;"><input type="text" class="otp-input" maxlength="1"><input type="text" class="otp-input" maxlength="1"><input type="text" class="otp-input" maxlength="1"><input type="text" class="otp-input" maxlength="1"><input type="text" class="otp-input" maxlength="1"><input type="text" class="otp-input" maxlength="1"></div></div>
        <div class="card"><h3 class="component-title">Linear Progress</h3><p>Visualizes the completion of a task.</p><div class="progress-bar" style="margin-top: 1rem;"><div id="linear-progress-bar" class="progress-bar-inner" style="width: 25%;"></div></div></div>
        <div class="card"><h3 class="component-title">Switch, Spinner & Spacer</h3><p>A collection of utility components.</p><div style="display:flex; flex-wrap:wrap; gap:2rem; align-items:center;"><label class="switch-label"><span class="spinner"></span><p style="margin:0;">Spinner</p></label><label class="switch-label"><div class="switch"><input type="checkbox" checked><span class="switch-slider"></span></div><span>Switch</span></label></div><p style="margin-top:1.5rem;">The Spacer below creates a 2rem vertical gap.</p><div class="spacer"></div><p>This text appears below the spacer.</p></div>
        <div class="card"><h3 class="component-title">Select</h3><p>A custom select component built for this design system.</p><div class="select-wrapper" id="custom-select" style="margin-top:1rem;"><div class="select-custom" role="button" aria-haspopup="listbox" aria-expanded="false"><span class="select-value">Select an option...</span><svg class="icon" viewBox="0 0 24 24"><path d="M19 9l-7 7-7-7"></path></svg></div><div class="select-options" role="listbox"><div class="select-option" role="option" data-value="Option 1">Option 1</div><div class="select-option" role="option" data-value="Option 2">Option 2</div><div class="select-option" role="option" data-value="Option 3">Option 3</div><div class="select-option" role="option" data-value="A much longer option to test text wrapping">A much longer option to test text wrapping</div></div></div></div>
        <div class="card"><h3 class="component-title">Slider</h3><p>Drag the thumb to select a value.</p><div class="slider-wrapper" id="slider-1" style="margin-top:1.5rem;"><div class="slider-track"><div class="slider-range"></div><div class="slider-thumb" role="slider" aria-valuemin="0" aria-valuemax="100" aria-valuenow="50"></div></div><span class="slider-value">50</span></div></div>
        <div class="card"><h3 class="component-title">Skeleton</h3><p>A placeholder for loading content.</p><div style="margin-top:1.5rem; display:flex; flex-direction:column; gap: 1.5rem;"><div class="skeleton" style="height: 60px; width: 100%;"></div><div style="display: flex; align-items: center; gap: 1rem;"><div class="skeleton skeleton-avatar"></div><div style="flex-grow: 1; display:flex; flex-direction:column; gap:0.5rem;"><div class="skeleton skeleton-text"></div><div class="skeleton skeleton-text"></div></div></div></div></div>
        <div class="card" style="grid-column: 1 / -1;"><h3 class="component-title">Snippet</h3><div class="snippet"><button class="copy-btn" aria-label="Copy code"><svg class="icon" viewBox="0 0 24 24" style="width:16px; height:16px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button><pre><code>function createSelect(id) {
    const wrapper = document.getElementById(id);
    // ... more code here
}</code></pre></div></div>
        <!-- ALL ORIGINAL SHOWCASE CARDS (UNCHANGED) END -->


        <!-- NEW & CORRECTED SHOWCASE CARDS START -->
        <div class="card">
            <h3 class="component-title">User & Tooltip</h3>
            <p>A simple component to display user info. Hover for a tooltip.</p>
            <div class="user" style="margin-top:1.5rem" data-tooltip="Online Now">
                <img class="avatar" src="https://i.pravatar.cc/150?u=b042581f4e29026704d" alt="John Appleseed">
                <div class="user-info">
                    <h4>John Appleseed</h4>
                    <p>Lead Engineer</p>
                </div>
            </div>
        </div>
      
        <div class="card">
            <h3 class="component-title">Textarea</h3>
            <p>Multi-line input for longer text and messages.</p>
            <div class="form-group" style="margin-top: 1rem;">
                <label for="feedback-area">Your Feedback</label>
                <textarea id="feedback-area" class="input-glass" placeholder="Tell us what you think..."></textarea>
            </div>
        </div>

        <div class="card" style="grid-column: 1 / -1;">
            <h3 class="component-title">Tabs</h3>
            <div class="tabs" id="main-tabs">
                <div class="tab-list" role="tablist">
                    <button class="tab-btn active" role="tab" aria-selected="true" data-target="#panel-1">Profile</button>
                    <button class="tab-btn" role="tab" aria-selected="false" data-target="#panel-2">Dashboard</button>
                    <button class="tab-btn" role="tab" aria-selected="false" data-target="#panel-3">Settings</button>
                    <div class="tab-indicator"></div>
                </div>
                <div id="panel-1" class="tab-panel active" role="tabpanel">
                    <p>This is the profile tab content. It contains user-specific information and personal details.</p>
                </div>
                <div id="panel-2" class="tab-panel" role="tabpanel">
                    <p>Welcome to your dashboard. All your key metrics and performance indicators are displayed here.</p>
                </div>
                <div id="panel-3" class="tab-panel" role="tabpanel">
                    <p>Manage your application settings, notification preferences, and security options from this tab.</p>
                </div>
            </div>
        </div>

        <div class="card" style="grid-column: 1 / -1;">
            <div class="table-container">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Component</th>
                            <th>Category</th>
                            <th>Status</th>
                            <th data-tooltip="Last updated by">Assignee</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Button</td>
                            <td>Interactive</td>
                            <td><span class="badge" style="background-color: #34c759;">Complete</span></td>
                            <td>Eva Roy</td>
                        </tr>
                        <tr>
                            <td>Card</td>
                            <td>Layout</td>
                            <td><span class="badge" style="background-color: #34c759;">Complete</span></td>
                            <td>John Appleseed</td>
                        </tr>
                        <tr>
                            <td>Date Picker</td>
                            <td>Form Input</td>
                            <td><span class="badge secondary">In Progress</span></td>
                            <td>Eva Roy</td>
                        </tr>
                        <tr>
                            <td>Table</td>
                            <td>Data Display</td>
                            <td><span class="badge" style="background-color: #ff9500;">Review</span></td>
                            <td>John Appleseed</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        <!-- NEW & CORRECTED SHOWCASE CARDS END -->

    </main>

    <!-- Global Elements -->
    <div id="toast-container" class="toast-container"></div>
    <div id="autocomplete-listbox" class="autocomplete-listbox" role="listbox"></div>
    <aside class="drawer" id="sample-drawer">
        <header class="drawer-header">
            <h4>Menu</h4>
            <button class="btn btn-secondary" id="drawer-close" aria-label="Close drawer" style="padding: 0.5rem; border-radius: var(--radius-full);">&times;</button>
        </header>
        <div class="drawer-body">
            <p>This panel contains supplementary content or navigation links, sliding in from the edge of the screen without disrupting the main flow.</p>
        </div>
    </aside>
    <div class="drawer-backdrop" id="drawer-backdrop"></div>
    <div class="modal-backdrop" id="modal-backdrop"></div>
    <div class="modal-dialog" id="sample-modal-2" role="dialog" aria-modal="true" aria-labelledby="modal-title-2">
      <div class="card modal-content">
        <header class="modal-header">
            <h3 id="modal-title-2">Terms of Service</h3>
            <button class="btn" id="modal-close-2" aria-label="Close modal">&times;</button>
        </header>
        <div class="modal-body">
            <p>By using our service, you agree to our terms. This modal appears on top of all content and requires user interaction to be dismissed.</p>
        </div>
      </div>
    </div>

    <script>
    document.addEventListener('DOMContentLoaded', () => {
        // --- NEW THEME SWITCHER LOGIC START ---
        const themeSwitcher = document.getElementById('theme-switcher');
        const themeButtons = themeSwitcher.querySelectorAll('button');
        const body = document.body;

        const applyTheme = (theme) => {
            if (theme === 'system') {
                const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                body.classList.toggle('dark-mode', systemPrefersDark);
            } else {
                body.classList.toggle('dark-mode', theme === 'dark');
            }
        };

        const updateButtonState = (activeTheme) => {
            themeButtons.forEach(button => {
                button.classList.toggle('active', button.dataset.theme === activeTheme);
            });
        };

        // Initialize theme on page load
        const savedTheme = localStorage.getItem('theme') || 'system';
        applyTheme(savedTheme);
        updateButtonState(savedTheme);

        // Add event listeners to buttons
        themeButtons.forEach(button => {
            button.addEventListener('click', () => {
                const newTheme = button.dataset.theme;
                localStorage.setItem('theme', newTheme);
                applyTheme(newTheme);
                updateButtonState(newTheme);
            });
        });

        // Listen for changes in OS theme preference
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
            const currentTheme = localStorage.getItem('theme');
            // Only update if the user has selected "system" mode
            if (currentTheme === 'system') {
                applyTheme('system');
            }
        });
        // --- NEW THEME SWITCHER LOGIC END ---

        // --- ALL ORIGINAL JAVASCRIPT (UNCHANGED) START ---
        document.querySelectorAll('.accordion-header').forEach(button => { const content = button.nextElementSibling; if (button.parentElement.classList.contains('active')) { content.style.maxHeight = content.scrollHeight + 'px'; } button.addEventListener('click', () => { const accordionItem = button.parentElement; const isExpanded = button.getAttribute('aria-expanded') === 'true'; button.setAttribute('aria-expanded', !isExpanded); accordionItem.classList.toggle('active', !isExpanded); content.style.maxHeight = !isExpanded ? content.scrollHeight + 'px' : '0px'; }); });
        document.getElementById('alert-trigger').addEventListener('click', () => { const toastContainer = document.getElementById('toast-container'); const toast = document.createElement('div'); toast.className = 'toast'; toast.setAttribute('role', 'alert'); toast.innerHTML = `<span class="badge" style="background-color: #34c759; color: white;">✓</span> <p>Your action was successful!</p>`; toastContainer.appendChild(toast); setTimeout(() => { toast.style.transition = 'opacity 0.3s ease'; toast.style.opacity = '0'; toast.addEventListener('transitionend', () => toast.remove()); }, 3000); });
        const autocompleteInput = document.getElementById('autocomplete-input'); const listbox = document.getElementById('autocomplete-listbox'); const fruits = ['Apple', 'Apricot', 'Avocado', 'Banana', 'Blackberry', 'Blueberry', 'Cherry', 'Coconut', 'Cranberry', 'Dragonfruit', 'Durian', 'Elderberry', 'Fig', 'Grape', 'Grapefruit', 'Guava', 'Honeydew', 'Jackfruit', 'Kiwi', 'Lemon', 'Lime', 'Lychee', 'Mango', 'Melon', 'Nectarine', 'Orange', 'Papaya', 'Passionfruit', 'Peach', 'Pear', 'Pineapple', 'Plum', 'Pomegranate', 'Raspberry', 'Strawberry', 'Tangerine', 'Watermelon']; let highlightIndex = -1; function hideListbox() { listbox.classList.remove('visible'); autocompleteInput.setAttribute('aria-expanded', 'false'); highlightIndex = -1; } function positionAndShowListbox(options) { listbox.innerHTML = ''; if (options.length === 0) { hideListbox(); return; } const inputRect = autocompleteInput.getBoundingClientRect(); const viewportHeight = window.innerHeight; const listboxMaxHeight = 200; const spaceBelow = viewportHeight - inputRect.bottom; const spaceAbove = inputRect.top; if (spaceBelow < listboxMaxHeight && spaceAbove > spaceBelow) { listbox.style.top = 'auto'; listbox.style.bottom = `${viewportHeight - inputRect.top + 8}px`; } else { listbox.style.bottom = 'auto'; listbox.style.top = `${inputRect.bottom + 8}px`; } listbox.style.left = `${inputRect.left}px`; listbox.style.width = `${inputRect.width}px`; options.forEach((option, index) => { const optionEl = document.createElement('div'); optionEl.className = 'autocomplete-option'; optionEl.textContent = option; optionEl.setAttribute('role', 'option'); optionEl.setAttribute('id', `option-${index}`); optionEl.addEventListener('mousedown', () => { autocompleteInput.value = option; hideListbox(); }); listbox.appendChild(optionEl); }); listbox.classList.add('visible'); autocompleteInput.setAttribute('aria-expanded', 'true'); highlightIndex = -1; } function updateHighlight() { const options = listbox.querySelectorAll('.autocomplete-option'); options.forEach((opt, index) => { if (index === highlightIndex) { opt.classList.add('highlighted'); autocompleteInput.setAttribute('aria-activedescendant', opt.id); opt.scrollIntoView({ block: 'nearest' }); } else { opt.classList.remove('highlighted'); } }); } autocompleteInput.addEventListener('input', () => { const query = autocompleteInput.value.toLowerCase(); const filteredOptions = query ? fruits.filter(f => f.toLowerCase().startsWith(query)) : []; positionAndShowListbox(filteredOptions); }); autocompleteInput.addEventListener('focus', () => { const query = autocompleteInput.value.toLowerCase(); const filteredOptions = query ? fruits.filter(f => f.toLowerCase().startsWith(query)) : []; if (filteredOptions.length > 0) { positionAndShowListbox(filteredOptions); } }); autocompleteInput.addEventListener('keydown', (e) => { if (!listbox.classList.contains('visible')) return; const options = listbox.querySelectorAll('.autocomplete-option'); if (options.length === 0) return; if (e.key === 'ArrowDown') { e.preventDefault(); highlightIndex = (highlightIndex + 1) % options.length; updateHighlight(); } else if (e.key === 'ArrowUp') { e.preventDefault(); highlightIndex = (highlightIndex - 1 + options.length) % options.length; updateHighlight(); } else if (e.key === 'Enter' && highlightIndex > -1) { e.preventDefault(); autocompleteInput.value = options[highlightIndex].textContent; hideListbox(); } else if (e.key === 'Escape') { hideListbox(); } }); autocompleteInput.addEventListener('blur', () => { setTimeout(hideListbox, 150); }); window.addEventListener('scroll', hideListbox, { passive: true }); window.addEventListener('resize', () => { if (listbox.classList.contains('visible')) { const query = autocompleteInput.value.toLowerCase(); const filteredOptions = query ? fruits.filter(f => f.toLowerCase().startsWith(query)) : []; positionAndShowListbox(filteredOptions); } });
        document.querySelector('#sample-chip .chip-close-btn')?.addEventListener('click', (e) => { const chip = e.currentTarget.closest('.chip'); chip.classList.add('disappearing'); chip.addEventListener('transitionend', () => { chip.remove(); }, { once: true }); });
        const progressCircle = document.querySelector('#circular-progress-indicator .progress-value'); const radius = progressCircle.r.baseVal.value; const circumference = radius * 2 * Math.PI; progressCircle.style.strokeDasharray = `${circumference} ${circumference}`; let progress = 0; setInterval(() => { progress = (progress + 10) % 101; const offset = circumference - progress / 100 * circumference; progressCircle.style.strokeDashoffset = offset; }, 1000); progressCircle.style.strokeDashoffset = circumference;
        function closeAllPopups(except) { document.querySelectorAll('.popover-wrapper, .select-wrapper, .popover-wrapper').forEach(wrapper => { if (wrapper !== except) { wrapper.querySelector('.popover, .dropdown-menu')?.classList.remove('visible'); if(wrapper.classList.contains('select-wrapper')) { wrapper.classList.remove('active'); wrapper.querySelector('[role="button"]').setAttribute('aria-expanded', 'false'); } } }); } document.addEventListener('click', (e) => { const wrapper = e.target.closest('.popover-wrapper, .select-wrapper'); if(!wrapper) closeAllPopups(); });
        const drawerTrigger = document.getElementById('drawer-trigger'); const drawerClose = document.getElementById('drawer-close'); const drawerBackdrop = document.getElementById('drawer-backdrop'); drawerTrigger.addEventListener('click', () => document.body.classList.add('drawer-open')); drawerClose.addEventListener('click', () => document.body.classList.remove('drawer-open')); drawerBackdrop.addEventListener('click', () => document.body.classList.remove('drawer-open'));
        document.getElementById('sample-form').addEventListener('submit', (e) => { e.preventDefault(); if (e.target.checkValidity()) { const toast = document.createElement('div'); toast.className = 'toast'; toast.setAttribute('role', 'alert'); toast.innerHTML = `<span class="badge" style="background-color: #34c759; color: white;">✓</span> <p>Form submitted!</p>`; document.getElementById('toast-container').appendChild(toast); setTimeout(() => { toast.style.transition = 'opacity 0.3s ease'; toast.style.opacity = '0'; toast.addEventListener('transitionend', () => toast.remove()); }, 3000); } else { const toast = document.createElement('div'); toast.className = 'toast'; toast.setAttribute('role', 'alert'); toast.innerHTML = `<span class="badge" style="background-color: #ff3b30; color: white;">!</span> <p>Please fix form errors.</p>`; document.getElementById('toast-container').appendChild(toast); setTimeout(() => { toast.style.transition = 'opacity 0.3s ease'; toast.style.opacity = '0'; toast.addEventListener('transitionend', () => toast.remove()); }, 3000); } });
        const dropdownTrigger = document.getElementById('dropdown-trigger'); const dropdownMenu = document.getElementById('dropdown-menu'); const dropdownIcon = dropdownTrigger.querySelector('.icon'); dropdownTrigger.addEventListener('click', (e) => { e.stopPropagation(); const wrapper = e.currentTarget.closest('.popover-wrapper'); closeAllPopups(wrapper); const shouldBeVisible = !dropdownMenu.classList.contains('visible'); if (shouldBeVisible) { const triggerRect = dropdownTrigger.getBoundingClientRect(); const spaceBelow = window.innerHeight - triggerRect.bottom; const DROPDOWN_HEIGHT_ESTIMATE = 150; dropdownMenu.classList.remove('above', 'below'); if (spaceBelow < DROPDOWN_HEIGHT_ESTIMATE && triggerRect.top > spaceBelow) { dropdownMenu.classList.add('above'); } else { dropdownMenu.classList.add('below'); } dropdownMenu.classList.add('visible'); dropdownIcon.style.transform = 'rotate(180deg)'; } else { dropdownMenu.classList.remove('visible'); dropdownIcon.style.transform = 'rotate(0deg)'; } });
        const navbar = document.getElementById('main-navbar'); window.addEventListener('scroll', () => { navbar.style.backdropFilter = window.scrollY > 20 ? 'blur(25px) saturate(180%)' : 'none'; navbar.style.background = window.scrollY > 20 ? 'var(--glass-bg)' : 'transparent'; navbar.style.boxShadow = window.scrollY > 20 ? 'var(--shadow-md)' : 'none'; }, { passive: true });
        const modalBackdrop = document.getElementById('modal-backdrop'); const modalDialog = document.getElementById('sample-modal-2'); const openModal = () => { modalBackdrop.classList.add('visible'); modalDialog.classList.add('visible'); }; const closeModal = () => { modalBackdrop.classList.remove('visible'); modalDialog.classList.remove('visible'); }; document.getElementById('modal-trigger-2').addEventListener('click', openModal); document.getElementById('modal-close-2').addEventListener('click', closeModal); modalBackdrop.addEventListener('click', closeModal);
        document.querySelector('.popover-trigger-2')?.addEventListener('click', (e) => { e.stopPropagation(); const trigger = e.currentTarget; const popover = trigger.nextElementSibling; const wrapper = e.currentTarget.closest('.popover-wrapper'); closeAllPopups(wrapper); const shouldBeVisible = !popover.classList.contains('visible'); if (shouldBeVisible) { const triggerRect = trigger.getBoundingClientRect(); const spaceBelow = window.innerHeight - triggerRect.bottom; const POPOVER_HEIGHT_ESTIMATE = popover.offsetHeight || 100; popover.classList.remove('above', 'below'); if (spaceBelow < POPOVER_HEIGHT_ESTIMATE && triggerRect.top > spaceBelow) { popover.classList.add('above'); } else { popover.classList.add('below'); } popover.classList.add('visible'); } else { popover.classList.remove('visible'); } });
        const listboxContainer = document.getElementById('sample-listbox'); const projects = ['Phoenix', 'Pegasus', 'Griffin', 'Hydra', 'Odyssey']; if (listboxContainer) { projects.forEach(project => { const item = document.createElement('div'); item.className = 'listbox-item'; item.textContent = project; item.setAttribute('role', 'option'); item.setAttribute('aria-selected', 'false'); item.addEventListener('click', () => { const isSelected = item.getAttribute('aria-selected') === 'true'; item.setAttribute('aria-selected', !isSelected); }); listboxContainer.appendChild(item); }); }
        const paginationContainer = document.getElementById('sample-pagination'); if (paginationContainer) { for (let i = 1; i <= 5; i++) { const pageBtn = document.createElement('button'); pageBtn.className = 'btn btn-secondary'; pageBtn.textContent = i; if (i === 1) pageBtn.classList.add('active'); pageBtn.addEventListener('click', (e) => { paginationContainer.querySelector('.btn.active').classList.remove('active'); e.currentTarget.classList.add('active'); }); paginationContainer.appendChild(pageBtn); } }
        document.getElementById('sample-radio-group')?.addEventListener('change', (e) => { document.getElementById('radio-output').textContent = `Selected: ${e.target.value}`; });
        document.querySelectorAll('.number-input-container').forEach(container => { const minusBtn = container.querySelector('button[aria-label="Decrement"]'); const plusBtn = container.querySelector('button[aria-label="Increment"]'); const input = container.querySelector('input'); minusBtn.addEventListener('click', () => { input.stepDown(); }); plusBtn.addEventListener('click', () => { input.stepUp(); }); });
        const otpContainer = document.getElementById('otp-container'); const otpInputs = [...otpContainer.querySelectorAll('.otp-input')]; otpInputs.forEach((input, index) => { input.addEventListener('input', () => { if (input.value && index < otpInputs.length - 1) { otpInputs[index + 1].focus(); } }); input.addEventListener('keydown', (e) => { if (e.key === 'Backspace' && !input.value && index > 0) { otpInputs[index - 1].focus(); } }); });
        setInterval(() => { const progressBar = document.getElementById('linear-progress-bar'); if (!progressBar) return; let currentWidth = parseFloat(progressBar.style.width) || 0; currentWidth = (currentWidth + 15) % 101; progressBar.style.width = `${currentWidth}%`; }, 1500);
        document.querySelectorAll('.snippet .copy-btn').forEach(btn => { btn.addEventListener('click', () => { const code = btn.nextElementSibling.innerText; navigator.clipboard.writeText(code).then(() => { const originalIcon = btn.innerHTML; btn.innerHTML = 'Copied!'; btn.style.background = '#34c759'; setTimeout(() => { btn.innerHTML = originalIcon; btn.style.background = ''; }, 2000); }); }); });
        const selectWrapper = document.getElementById('custom-select'); if(selectWrapper) { const selectCustom = selectWrapper.querySelector('.select-custom'); const selectValue = selectWrapper.querySelector('.select-value'); const selectOptions = selectWrapper.querySelector('.select-options'); selectCustom.addEventListener('click', (e) => { e.stopPropagation(); closeAllPopups(selectWrapper); const shouldBeVisible = !selectWrapper.classList.contains('active'); if (shouldBeVisible) { const triggerRect = selectCustom.getBoundingClientRect(); const spaceBelow = window.innerHeight - triggerRect.bottom; const OPTIONS_HEIGHT_ESTIMATE = selectOptions.offsetHeight || 150; selectOptions.classList.remove('above', 'below'); if (spaceBelow < OPTIONS_HEIGHT_ESTIMATE && triggerRect.top > spaceBelow) { selectOptions.classList.add('above'); } else { selectOptions.classList.add('below'); } } selectWrapper.classList.toggle('active'); selectCustom.setAttribute('aria-expanded', shouldBeVisible); }); selectWrapper.querySelectorAll('.select-option').forEach(option => { option.addEventListener('click', () => { selectValue.textContent = option.dataset.value; selectWrapper.classList.remove('active'); selectCustom.setAttribute('aria-expanded', 'false'); }); }); }
        const sliderWrapper = document.getElementById('slider-1'); if(sliderWrapper){ const thumb = sliderWrapper.querySelector('.slider-thumb'); const track = sliderWrapper.querySelector('.slider-track'); const range = sliderWrapper.querySelector('.slider-range'); const valueDisplay = sliderWrapper.querySelector('.slider-value'); const updateSlider = (percent) => { percent = Math.max(0, Math.min(100, percent)); range.style.width = `${percent}%`; thumb.style.left = `${percent}%`; const value = Math.round(percent); valueDisplay.textContent = value; thumb.setAttribute('aria-valuenow', value); }; const handleMove = (e) => { const trackRect = track.getBoundingClientRect(); const clientX = e.touches ? e.touches[0].clientX : e.clientX; let percent = ((clientX - trackRect.left) / trackRect.width) * 100; updateSlider(percent); }; const handleMouseUp = () => { document.removeEventListener('mousemove', handleMove); document.removeEventListener('mouseup', handleMouseUp); }; const handleTouchEnd = () => { document.removeEventListener('touchmove', handleMove); document.removeEventListener('touchend', handleTouchEnd); }; thumb.addEventListener('mousedown', (e) => { e.preventDefault(); document.addEventListener('mousemove', handleMove); document.addEventListener('mouseup', handleMouseUp); }); thumb.addEventListener('touchstart', (e) => { document.addEventListener('touchmove', handleMove); document.addEventListener('touchend', handleTouchEnd); }); track.addEventListener('click', handleMove); updateSlider(50); }
      
        // Corrected Tabs Logic
        document.querySelectorAll('.tabs').forEach(tabsContainer => {
            const tabList = tabsContainer.querySelector('.tab-list');
            const tabButtons = tabsContainer.querySelectorAll('.tab-btn');
            const tabIndicator = tabsContainer.querySelector('.tab-indicator');
            const tabPanels = tabsContainer.querySelectorAll('.tab-panel');

            function moveIndicator(targetTab) {
                if(!targetTab) return;
                tabIndicator.style.width = `${targetTab.offsetWidth}px`;
                tabIndicator.style.left = `${targetTab.offsetLeft}px`;
            }
          
            moveIndicator(tabList.querySelector('.active'));

            tabButtons.forEach(button => {
                button.addEventListener('click', () => {
                    tabButtons.forEach(btn => { btn.classList.remove('active'); btn.setAttribute('aria-selected', 'false'); });
                     tabPanels.forEach(panel => panel.classList.remove('active'));
                    button.classList.add('active');
                    button.setAttribute('aria-selected', 'true');
                    const targetPanel = tabsContainer.querySelector(button.dataset.target);
                    if(targetPanel) targetPanel.classList.add('active');
                    moveIndicator(button);
                });
            });
            window.addEventListener('resize', () => moveIndicator(tabList.querySelector('.active')));
        });
    });
    </script>
</body>
</html>

```
# Lebanese-Maintenance-Services

## Project Overview

**Lebanese Maintenance Services** is a bilingual home maintenance platform connecting customers with verified service providers across Lebanon.

### Technologies Used
- **Frontend**: HTML, CSS, JavaScript
- **Backend**: PHP
- **Database**: MySQL

### Features

#### Customers
- **Sign up:** Email verification via one-time codes, plus tokenized password reset.
- **Browse Providers:** Search and filter verified providers by category, location, and price.
- **Book Appointments:** Choose from a provider's available slots and submit a request with problem photos.
- **Track Requests:** View request status (Pending, Confirmed, Completed, Cancelled) and cancel or request cancellation.
- **Chat:** Real-time messaging with providers per request, plus a separate live chat channel with admin support.
- **Rate & Review:** Leave star ratings and written reviews after completed requests.
Location Pinning: Set a home location on an interactive map for providers to locate them.

#### Service Providers
- **Profile Management:** Edit bio, photo, phone, and request location changes (subject to admin approval).
- **Service Categories & Pricing:** Select offered categories and set a visit price for each.
- **Appointment Slots:** Create and delete available time slots.
- **Manage Requests:** Accept, confirm, complete, or cancel customer requests, and set estimated/final pricing.
- **Chat:** Communicate with customers per request, and with the admin team directly.
Category Requests: Propose new service categories for admin review.

#### Admin
- **Provider Verification & Suspension:** Approve providers before they appear publicly, and suspend/unsuspend any account.
- **Service Category Management:** Create, edit, delete, and approve/reject provider-submitted categories.
- **Site Settings:** Configure the public home page — hero content, features, highlight images, featured provider/review, and bilingual (English/Arabic) text.
- **Reviews & Interactions Dashboard:** Monitor all platform reviews and every customer–provider interaction, including chat history.
- **Location Requests:** Approve or reject provider location change requests.
- **Live Chat Support:** Respond to direct messages from customers and providers.

### Backend Structure
- **Security:** Native PDO prepared statements throughout, CSRF tokens on all state-changing forms, tokenized password resets, and email OTP verification.
- **Bilingual Support:** A custom language/translation layer (English & Arabic) with RTL layout switching and Arabic numeral conversion.
- **JSON-Backed Stores:** Lightweight flat-file JSON stores for provider verification and account suspension state.
- **Custom Mailer:** Hand-rolled SMTP client for verification and password-reset emails, with a PHP mail() fallback.

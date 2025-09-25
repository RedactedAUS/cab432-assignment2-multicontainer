// external-apis.js - Clear External API Integration
// Fixed version with syntax error corrected

const axios = require('axios');

class ExternalAPIService {
  constructor() {
    this.timeout = 10000; // 10 second timeout
  }

  // EXTERNAL API 1: OMDB Movie Database API
  async getMovieInfo(title) {
    try {
      console.log(`ðŸŒ EXTERNAL API CALL: Fetching movie info for "${title}"`);
      
      const response = await axios.get('http://www.omdbapi.com/', {
        params: {
          t: title,
          apikey: 'trilogy', // Demo key
          plot: 'full'
        },
        timeout: this.timeout
      });

      if (response.data.Response === 'False') {
        throw new Error('Movie not found in OMDB');
      }

      console.log(`âœ… EXTERNAL API SUCCESS: Got movie data for "${title}"`);
      
      return {
        source: 'omdb_api',
        title: response.data.Title,
        year: response.data.Year,
        rated: response.data.Rated,
        genre: response.data.Genre,
        director: response.data.Director,
        actors: response.data.Actors,
        plot: response.data.Plot,
        poster: response.data.Poster,
        imdbRating: response.data.imdbRating,
        imdbID: response.data.imdbID,
        retrieved_at: new Date().toISOString()
      };

    } catch (error) {
      console.error(`âŒ EXTERNAL API ERROR (OMDB):`, error.message);
      throw new Error(`OMDB API Error: ${error.message}`);
    }
  }

  // EXTERNAL API 2: JSONPlaceholder for Mock Video Comments/Reviews
  async getVideoReviews(videoId) {
    try {
      console.log(`ðŸŒ EXTERNAL API CALL: Fetching reviews for video ${videoId}`);
      
      const response = await axios.get('https://jsonplaceholder.typicode.com/comments', {
        params: {
          postId: (videoId % 10) + 1 // Map video ID to post ID 1-10
        },
        timeout: this.timeout
      });

      console.log(`âœ… EXTERNAL API SUCCESS: Got ${response.data.length} reviews`);
      
      return response.data.map(comment => ({
        source: 'jsonplaceholder_api',
        id: comment.id,
        reviewer_name: comment.name,
        reviewer_email: comment.email,
        review_text: comment.body,
        retrieved_at: new Date().toISOString()
      }));

    } catch (error) {
      console.error(`âŒ EXTERNAL API ERROR (JSONPlaceholder):`, error.message);
      throw new Error(`Reviews API Error: ${error.message}`);
    }
  }

  // EXTERNAL API 3: Cat Facts API for Random Content Generation
  async getRandomContent() {
    try {
      console.log(`ðŸŒ EXTERNAL API CALL: Fetching random content`);
      
      const response = await axios.get('https://catfact.ninja/fact', {
        timeout: this.timeout
      });

      console.log(`âœ… EXTERNAL API SUCCESS: Got random content`);
      
      return {
        source: 'catfacts_api',
        type: 'random_fact',
        content: response.data.fact,
        length: response.data.length,
        retrieved_at: new Date().toISOString()
      };

    } catch (error) {
      console.error(`âŒ EXTERNAL API ERROR (Cat Facts):`, error.message);
      throw new Error(`Random Content API Error: ${error.message}`);
    }
  }

  // EXTERNAL API 4: REST Countries API for Location-based Content
  async getCountryInfo(countryCode) {
    try {
      console.log(`ðŸŒ EXTERNAL API CALL: Fetching country info for ${countryCode}`);
      
      const response = await axios.get(`https://restcountries.com/v3.1/alpha/${countryCode}`, {
        timeout: this.timeout
      });

      const country = response.data[0];
      
      console.log(`âœ… EXTERNAL API SUCCESS: Got country data for ${country.name.common}`);
      
      return {
        source: 'restcountries_api',
        name: country.name.common,
        official_name: country.name.official,
        capital: country.capital?.[0],
        region: country.region,
        population: country.population,
        languages: Object.values(country.languages || {}),
        currencies: Object.keys(country.currencies || {}),
        flag: country.flag,
        retrieved_at: new Date().toISOString()
      };

    } catch (error) {
      console.error(`âŒ EXTERNAL API ERROR (REST Countries):`, error.message);
      throw new Error(`Country API Error: ${error.message}`);
    }
  }

  // EXTERNAL API 5: Advice Slip API for Content Suggestions
  async getAdvice() {
    try {
      console.log(`ðŸŒ EXTERNAL API CALL: Fetching advice`);
      
      const response = await axios.get('https://api.adviceslip.com/advice', {
        timeout: this.timeout
      });

      console.log(`âœ… EXTERNAL API SUCCESS: Got advice`);
      
      return {
        source: 'adviceslip_api',
        advice_id: response.data.slip.id,
        advice: response.data.slip.advice,
        retrieved_at: new Date().toISOString()
      };

    } catch (error) {
      console.error(`âŒ EXTERNAL API ERROR (Advice Slip):`, error.message);
      throw new Error(`Advice API Error: ${error.message}`);
    }
  }

  // Helper method to test all external APIs
  async testAllAPIs() {
    const results = {
      timestamp: new Date().toISOString(),
      tests: []
    };

    // Test OMDB
    try {
      const movieData = await this.getMovieInfo('The Matrix');
      results.tests.push({
        api: 'OMDB',
        status: 'SUCCESS',
        data: movieData
      });
    } catch (error) {
      results.tests.push({
        api: 'OMDB', 
        status: 'FAILED',
        error: error.message
      });
    }

    // Test JSONPlaceholder
    try {
      const reviews = await this.getVideoReviews(1);
      results.tests.push({
        api: 'JSONPlaceholder',
        status: 'SUCCESS',
        count: reviews.length
      });
    } catch (error) {
      results.tests.push({
        api: 'JSONPlaceholder',
        status: 'FAILED', 
        error: error.message
      });
    }

    // Test Cat Facts
    try {
      const fact = await this.getRandomContent();
      results.tests.push({
        api: 'CatFacts',
        status: 'SUCCESS',
        content_length: fact.content.length
      });
    } catch (error) {
      results.tests.push({
        api: 'CatFacts',
        status: 'FAILED',
        error: error.message
      });
    }

    // Test REST Countries
    try {
      const country = await this.getCountryInfo('US');
      results.tests.push({
        api: 'RESTCountries',
        status: 'SUCCESS',
        country: country.name
      });
    } catch (error) {
      results.tests.push({
        api: 'RESTCountries',
        status: 'FAILED',
        error: error.message
      });
    }

    // Test Advice Slip
    try {
      const advice = await this.getAdvice();
      results.tests.push({
        api: 'AdviceSlip',
        status: 'SUCCESS',
        advice_id: advice.advice_id
      });
    } catch (error) {
      results.tests.push({
        api: 'AdviceSlip',
        status: 'FAILED',
        error: error.message
      });
    }

    return results;
  }
}

module.exports = new ExternalAPIService();
